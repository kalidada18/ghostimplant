#!/usr/bin/env python3
"""
Persistence tests for the SQLite-backed C2 server.

The server used to keep everything in process memory, so this suite is the
mechanical proof of the durability claim: a restart must keep sessions, task
queues, results, the audit trail and the staged payload, while resetting what a
restart is supposed to reset (the ECDH keypair and the channel keys).

A "restart" is simulated the way the real one behaves: close and reopen the
database (server/db.py) and clear in-process channel keys. Beacons here are
plaintext — channel crypto is covered end-to-end by tests/test_protocol.py, and
these tests are about what survives on disk, not about the wire.

Run:  python tests/test_persistence.py
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))

import c2_server as srv   # noqa: E402
import db as dbmod        # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

PASS = 0
FAIL = 0
BT = "test-beacon-token-not-for-operational-use"
OT = "test-operator-token-not-for-operational-use"


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ok] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


# ── tiny plaintext client ─────────────────────────────────────────────────────
_c = srv.app.test_client()


def hdr_beacon(sid):
    return {"X-Beacon-Token": BT, "X-Session-ID": sid, "Content-Type": "application/json"}


def hdr_op():
    return {"X-Operator-Token": OT, "Content-Type": "application/json"}


def beacon(sid, n=1, ack="", run="run01"):
    body = {"session": sid, "run": run, "n": n, "ack": ack,
            "recon": {"hostname": "LAB-VM", "user": "tester", "build": 22631,
                      "elevated": True}}
    return _c.post("/beacon", data=json.dumps(body), headers=hdr_beacon(sid))


def task(sid, cmd):
    return _c.post("/task", json={"session": sid, "cmd": cmd}, headers=hdr_op())


def result(sid, tid, output, status="ok", n=1):
    body = {"session": sid, "tid": tid, "status": status, "n": n, "output": output}
    return _c.post("/result", data=json.dumps(body), headers=hdr_beacon(sid))


def results(sid):
    r = _c.get(f"/results/{sid}", headers=hdr_op())
    return r.get_json().get("results", []) if r.status_code == 200 else []


def audit():
    return _c.get("/audit?limit=500", headers=hdr_op()).get_json()["entries"]


def sessions():
    return _c.get("/sessions", headers=hdr_op()).get_json()


def restart():
    """Simulate a process restart: reopen the DB, drop in-process channel keys."""
    srv._channel_keys.clear()
    srv._reopen_store(srv._store.path, force=True)


def main():
    srv._CFG["auto_accept"] = True
    srv._CFG["beacon_token"] = BT
    srv._CFG["operator_token"] = OT

    print("── defaults: importing the server has no filesystem side effects ──")
    check("default store is in-memory", srv.CFG_DEFAULTS["db_path"] == ":memory:")

    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "lab.db")
        srv._reopen_store(db)
        check("durable store is a file", os.path.exists(db))
        check("schema version recorded", srv._store.schema_version() == dbmod.SCHEMA_VERSION)

        print("── sessions, tasks and results survive a restart ──")
        sid = "persist01|tester"
        check("first beacon accepted", beacon(sid).status_code == 200)
        check("session row created", srv._store.session(sid) is not None)

        t1 = task(sid, "whoami").get_json()["tid"]
        r = beacon(sid, n=2)
        check("task served", r.get_json()["tid"] == t1 and r.get_json()["cmd"] == "whoami")
        check("task state is sent", srv._store.task_states(sid)["sent"] == 1)

        restart()
        check("session survived restart", srv._store.session(sid) is not None)
        check("task queue survived restart", srv._store.task_states(sid)["sent"] == 1)
        r = beacon(sid, n=3)
        check("unacked task re-served after restart",
              r.get_json()["tid"] == t1, repr(r.get_json()))

        check("result accepted", result(sid, t1, "whoami output").status_code == 200)
        check("result stored", len(results(sid)) == 1)

        restart()
        check("result survived restart", len(results(sid)) == 1)
        r = result(sid, t1, "whoami output")
        check("duplicate result flagged after restart", r.get_json().get("dup") is True,
              repr(r.get_json()))
        check("no second result stored", len(results(sid)) == 1)
        check("task still completed, not re-queued",
              srv._store.task_states(sid) == {"queued": 0, "sent": 0, "acked": 0, "done": 0})

        print("── audit trail survives a restart ──")
        entries = audit()
        actions = {e["action"] for e in entries}
        check("task_queued audited", "task_queued" in actions, repr(sorted(actions)))
        check("result_dup audited", "result_dup" in actions, repr(sorted(actions)))
        restart()
        check("audit survived restart", len(audit()) >= len(entries))

        print("── staged payload survives a restart ──")
        blob = b"GHOST-LAB-PAYLOAD\x00\x01\x02" * 64
        r = _c.post("/payload", data=blob,
                    headers={"X-Operator-Token": OT, "X-Payload-Name": "test.bin"})
        check("payload uploaded", r.status_code == 200)
        restart()
        r = _c.get("/payload", headers={"X-Beacon-Token": BT, "X-Session-ID": sid})
        check("payload survived restart", r.status_code == 200 and r.data == blob)
        check("payload keeps its name", srv._store.payload()["name"] == "test.bin")

        print("── caps keep working (and keep working after a restart) ──")
        cap_sid = "caps01|tester"
        beacon(cap_sid)
        old_results, old_queue = srv._CFG["result_cap"], srv._CFG["task_queue_max"]
        srv._CFG["result_cap"] = 3
        for i in range(5):
            result(cap_sid, f"cap{i}", f"out{i}")
        check("result cap enforced", len(results(cap_sid)) == 3, len(results(cap_sid)))
        check("newest results kept", [x["tid"] for x in results(cap_sid)] ==
              ["cap2", "cap3", "cap4"], repr([x["tid"] for x in results(cap_sid)]))
        srv._CFG["result_cap"] = old_results

        srv._CFG["task_queue_max"] = 2
        check("queue under cap accepts", task(cap_sid, "a").status_code == 200)
        check("queue under cap accepts again", task(cap_sid, "b").status_code == 200)
        check("queue at cap rejects", task(cap_sid, "c").status_code == 429)
        restart()
        check("queue cap holds after restart", task(cap_sid, "c").status_code == 429)
        srv._CFG["task_queue_max"] = old_queue

        print("── kill: session is told to exit and /sessions stays alive ──")
        # Regression: the old in-memory kill pushed a bare string into the task
        # deque, so every later t["state"] walk raised TypeError — /sessions and
        # the next beacon returned 500 after a kill.
        ksid = "killsess|tester"
        beacon(ksid)
        task(ksid, "whoami")
        r = _c.delete(f"/sessions/{ksid}", headers=hdr_op())
        check("kill accepted", r.status_code == 200, r.status_code)
        r = _c.get("/sessions", headers=hdr_op())
        check("/sessions survives a kill", r.status_code == 200, r.status_code)
        row = next((s for s in r.get_json() if s["session"] == ksid), None)
        check("killed session reported", row is not None and row["status"] == "killed",
              repr(row))
        check("killed queue drained",
              row is not None and row["task_states"] ==
              {"queued": 0, "sent": 0, "acked": 0, "done": 0}, repr(row))
        check("killed session is told to exit",
              beacon(ksid).get_json().get("cmd") == "exit")

        print("── janitor prunes sessions and everything they own ──")
        psid = "prunesess|tester"
        beacon(psid)
        task(psid, "whoami")
        result(psid, "orphan", "output")
        dead = srv._store.prune_sessions(time.time() + 1)   # cutoff in the future
        check("prune reported the session", psid in dead, repr(dead))
        check("session row gone", srv._store.session(psid) is None)
        check("its results are gone", results(psid) == [])
        check("its task rows are gone",
              srv._store.task_states(psid) == {"queued": 0, "sent": 0, "acked": 0, "done": 0})

        srv._store.close()

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
