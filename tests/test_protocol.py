#!/usr/bin/env python3
"""
End-to-end test of the GHOST C2 channel protocol v2 (ECDH P-256 handshake +
AES-256-GCM wire encryption + monotonic counters + task ids + acks) against
the Flask server, using its test client.

The FakeImplant class mirrors the implant's SendBeacon/SendResult logic in
src/c2.cpp: encrypt only once a server public point ("spk") has been seen,
adopt spk on every response, decrypt "e":1 cmd blobs, fall back to plaintext
after a rejection and re-handshake, bump counters, ack tasks, dedup results.

Run:  python tests/test_protocol.py
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))

import c2_server as srv  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

# Windows consoles default to cp1252 and raise UnicodeEncodeError on the
# box-drawing section headers printed below. Force UTF-8 with replacement so the
# suite runs from a plain PowerShell prompt.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

PASS = 0
FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ok] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


class FakeImplant:
    """Mirrors src/c2.cpp channel logic (SendBeacon / SendResult)."""

    def __init__(self, sid, run="a1b2c3d4"):
        self.sid = sid
        self.run = run
        self.priv = ec.generate_private_key(ec.SECP256R1())
        pub = self.priv.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)[1:]  # X||Y big-endian
        self.pub_b64 = base64.b64encode(pub).decode()
        self.srv_pub_b64 = None
        self.key = None
        self.tx_n = 0            # implant -> server counter
        self.rx_srv_n = 0        # server -> implant counter (last accepted)
        self.pending_ack = ""    # tid to ack in the next beacon
        self.c = srv.app.test_client()

    def _derive(self, srv_pub_b64):
        xy = base64.b64decode(srv_pub_b64)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + xy)
        return hashlib.sha256(self.priv.exchange(ec.ECDH(), peer)).digest()

    def _headers(self, enc=False):
        h = {"X-Beacon-Token": srv._CFG["beacon_token"],
             "X-Pub-Key": self.pub_b64,
             "X-Session-ID": self.sid,
             "Content-Type": "application/json"}
        if enc and self.key:
            h["X-Enc"] = "1"
        return h

    def _consume(self, resp_body):
        """Adopt spk + server counter, then extract (cmd, tid) — implant order."""
        spk = resp_body.get("spk", "")
        if spk and spk != self.srv_pub_b64:
            key = self._derive(spk)
            if key:
                self.key = key
                self.srv_pub_b64 = spk
                self.rx_srv_n = 0        # new server epoch
        cmd, tid = resp_body.get("cmd", ""), resp_body.get("tid", "")
        if resp_body.get("e") == 1 and cmd and self.key:
            blob = json.loads(
                AESGCM(self.key).decrypt(
                    base64.b64decode(cmd)[:12],
                    base64.b64decode(cmd)[28:] + base64.b64decode(cmd)[12:28],
                    None))
            srv_n = blob.get("n", 0)
            if srv_n <= self.rx_srv_n:
                raise AssertionError(f"replayed server counter {srv_n} <= {self.rx_srv_n}")
            self.rx_srv_n = srv_n
            cmd, tid = blob.get("cmd", ""), blob.get("tid", "")
        if tid:
            self.pending_ack = tid       # ack it in the next beacon
        return cmd, tid

    def beacon(self, force_plaintext=False):
        self.tx_n += 1
        body = {"session": self.sid, "run": self.run, "n": self.tx_n,
                "ack": self.pending_ack,
                "recon": {"hostname": "LAB-VM", "user": "tester",
                          "build": 22631, "elevated": True}}
        if self.key and not force_plaintext:
            data = srv._enc_blob(self.key, body)
            enc = True
        else:
            data = json.dumps(body)
            enc = False
        r = self.c.post("/beacon", data=data, headers=self._headers(enc=enc))
        if r.status_code != 200:
            return None, None, r
        cmd, tid = self._consume(r.get_json())
        self.pending_ack = ""            # ack consumed by this successful beacon
        return cmd, tid, r

    def result(self, tid, output, status="ok", replay_n=None):
        self.tx_n += 1
        body = {"session": self.sid, "tid": tid, "status": status,
                "n": self.tx_n if replay_n is None else replay_n, "output": output}
        data = srv._enc_blob(self.key, body) if self.key else json.dumps(body)
        r = self.c.post("/result", data=data, headers=self._headers(enc=bool(self.key)))
        return r

    def raw_result(self, payload_bytes):
        """Re-post a previously captured encrypted payload (replay attack)."""
        return self.c.post("/result", data=payload_bytes, headers=self._headers(enc=True))

    def push_task(self, cmd):
        r = self.c.post("/task", json={"session": self.sid, "cmd": cmd},
                        headers={"X-Operator-Token": srv._CFG["operator_token"]})
        assert r.status_code == 200, f"task -> {r.status_code}"
        return r.get_json()["tid"]

    def results(self):
        r = self.c.get(f"/results/{self.sid}",
                       headers={"X-Operator-Token": srv._CFG["operator_token"]})
        assert r.status_code == 200
        return r.get_json()

    def tasks_view(self):
        r = self.c.get("/sessions", headers={"X-Operator-Token": srv._CFG["operator_token"]})
        assert r.status_code == 200
        for s in r.get_json():
            if s["session"] == self.sid:
                return s
        return {}


def main():
    srv._CFG["auto_accept"] = True
    sid = "ab12cd34|tester"

    print("── handshake + encrypted round trip ──")
    imp = FakeImplant(sid)
    cmd, tid, r = imp.beacon(force_plaintext=True)   # first beacon: bootstrap
    check("first beacon returns spk", bool(imp.srv_pub_b64))
    check("server stored channel key", srv._sessions[sid].get("key") == imp.key)
    check("run id recorded", srv._sessions[sid].get("run") == "a1b2c3d4")
    check("first beacon cmd (encrypted) = sleep", cmd == "sleep", repr(cmd))

    t1 = imp.push_task('whoami && echo "quoted arg" ünïcode')
    cmd, tid, r = imp.beacon()
    check("task delivered with matching tid", tid == t1 and cmd.startswith("whoami"), repr((cmd, tid)))

    r = imp.result(tid, 'done\nline "two" — ünïcode ✓')
    got = imp.results()["results"][-1]
    check("result round trip (tid + status + output)",
          got["tid"] == t1 and got["status"] == "ok" and got["output"].endswith("ünïcode ✓"),
          repr(got))

    print("── task lifecycle: ack, completion, no retry ──")
    check("task state done", srv._tasks[sid][0]["state"] == "done")
    cmd2, tid2, _ = imp.beacon()
    check("beacon after done = sleep", cmd2 == "sleep" and tid2 == "", repr((cmd2, tid2)))
    check("ack consumed", imp.pending_ack == "")

    print("── retry: unacked task re-served (at-least-once) ──")
    t2 = imp.push_task("dir")
    cmd3, tid3, _ = imp.beacon()
    check("task2 delivered", cmd3 == "dir" and tid3 == t2, repr((cmd3, tid3)))
    cmd3b, tid3b, _ = imp.beacon()          # no result yet → re-served
    check("unacked task re-served", cmd3b == "dir" and tid3b == t2, repr((cmd3b, tid3b)))

    print("── dedup: duplicate result ignored, task still completed ──")
    r1 = imp.result(t2, "dir output here")
    check("first result stored", len(imp.results()["results"]) == 2)
    r2 = imp.result(t2, "dir output here")  # retransmit
    check("dup result acknowledged", r2.get_json().get("dup") is True, repr(r2.get_json()))
    check("no extra result stored", len(imp.results()["results"]) == 2)
    cmd4, tid4, _ = imp.beacon()
    check("task done → sleep", cmd4 == "sleep" and tid4 == "")
    check("server task state done", all(t["state"] == "done" for t in srv._tasks[sid]))

    print("── session view exposes protocol state ──")
    view = imp.tasks_view()
    check("run visible", view.get("run") == "a1b2c3d4", repr(view.get("run")))
    check("done tasks pruned from queue", view.get("task_states") == {"queued": 0, "sent": 0, "acked": 0, "done": 0}, repr(view.get("task_states")))
    check("no key material leaked", "key" not in view and "last_rx_n" not in view)

    print("── replay protection ──")
    t3 = imp.push_task("whoami")
    cmd5, tid5, _ = imp.beacon()
    n_before = imp.tx_n
    r_replay = imp.raw_result(srv._enc_blob(imp.key, {
        "session": sid, "tid": tid5, "status": "ok", "n": imp.tx_n - 1, "output": "evil"}))
    check("replayed counter rejected", r_replay.status_code == 400, r_replay.status_code)
    # legitimate result still accepted afterwards
    r_ok = imp.result(tid5, "whoami output")
    check("legit result after replay attempt", r_ok.status_code == 200)

    print("── server restart (keypair rotated, store wiped) ──")
    srv._SRV_ECDH = ec.generate_private_key(ec.SECP256R1())
    srv._SRV_PUB_B64 = base64.b64encode(
        srv._SRV_ECDH.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)[1:]).decode()
    srv._sessions.clear()
    srv._tasks.clear()
    srv._results.clear()
    srv._done_tids.clear()
    cmd6, tid6, _ = imp.beacon()            # implant still on old epoch
    check("rehandshake response plaintext + new spk", cmd6 == "sleep")
    check("implant adopted new server pub", imp.srv_pub_b64 == srv._SRV_PUB_B64)
    cmd7, tid7, _ = imp.beacon()
    check("beacon after re-handshake encrypted OK", cmd7 == "sleep")

    imp.push_task("ver")
    cmd8, tid8, _ = imp.beacon()
    check("task served after re-handshake", cmd8 == "ver", repr(cmd8))
    check("server stored rotated key", srv._sessions[sid].get("key") == imp.key)

    print("── blob helpers round trip ──")
    blob = srv._enc_blob(imp.key, {"x": 'a"b\\c\nü'})
    check("enc/dec round trip", srv._dec_blob(imp.key, blob) == {"x": 'a"b\\c\nü'})

    print("── wire base64 is canonical (implant decoder is strict) ──")
    # src/utils.cpp Base64Decode now rejects '=' in the first two positions of a
    # quartet, padding in any non-final quartet, and any alphabet char after a
    # pad. Mirror those rules and push every string the server actually emits
    # through them, so the tightened implant decoder can never start refusing a
    # legitimate frame.
    ALPHA = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

    def strict_b64_ok(s):
        if len(s) % 4:
            return False
        for i in range(0, len(s), 4):
            last = (i + 4 == len(s))
            saw_pad = False
            for j, c in enumerate(s[i:i + 4]):
                if c == '=':
                    if j < 2 or not last:
                        return False
                    saw_pad = True
                elif saw_pad or c not in ALPHA:
                    return False
        return True

    check("server spk passes strict decoder", strict_b64_ok(srv._SRV_PUB_B64))
    check("adopted server pub passes strict decoder", strict_b64_ok(imp.srv_pub_b64))
    check("wire blob passes strict decoder",
          strict_b64_ok(srv._enc_blob(imp.key, {"output": ""})))
    # The mirror needs teeth or the three checks above prove nothing.
    check("mirror rejects mid-quartet pad", not strict_b64_ok("AB=C"))
    check("mirror rejects leading pad", not strict_b64_ok("A==="))
    check("mirror rejects pad in non-final quartet", not strict_b64_ok("AB==CD=="))
    check("mirror accepts canonical form", strict_b64_ok("QQ=="))

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
