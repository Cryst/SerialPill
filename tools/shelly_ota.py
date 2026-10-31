#!/usr/bin/env python3
"""Upload a firmware package to a Shelly Gen2+/Gen3 device, exactly like the web UI's
"Update from file" (RPC OTA.Start + OTA.Write chunks).

Usage: python shelly_ota.py <ip> <package.zip> [--password PASS]
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import time
import urllib.request

CHUNK = 2048


class Rpc:
    def __init__(self, ip, password=None):
        self.url = f"http://{ip}/rpc"
        self.password = password
        self.auth = None

    def call(self, method, params=None, timeout=30):
        body = {"id": 1, "method": method, "params": params or {}}
        if self.auth:
            body["auth"] = self.auth
        req = urllib.request.Request(self.url, json.dumps(body).encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.load(r)
        err = resp.get("error")
        if err and err.get("code") == 401 and self.password and not self.auth:
            chal = json.loads(err["message"])
            sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
            cnonce = os.urandom(8).hex()
            ha1 = sha(f"admin:{chal['realm']}:{self.password}")
            ha2 = sha("dummy_method:dummy_uri")
            self.auth = {"realm": chal["realm"], "username": "admin", "nonce": chal["nonce"], "cnonce": cnonce,
                         "response": sha(f"{ha1}:{chal['nonce']}:{chal.get('nc', 1)}:{cnonce}:auth:{ha2}"),
                         "algorithm": "SHA-256"}
            return self.call(method, params, timeout)
        if err:
            raise RuntimeError(f"{method}: {err}")
        return resp.get("result")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ip")
    ap.add_argument("package")
    ap.add_argument("--password")
    a = ap.parse_args()
    rpc = Rpc(a.ip, a.password)
    data = open(a.package, "rb").read()
    info = rpc.call("Shelly.GetDeviceInfo")
    print(f"{info['id']} {info.get('app')} fw {info.get('ver')} <- {os.path.basename(a.package)} ({len(data)} B)")
    rpc.call("OTA.Start", {"size": len(data)})
    off, t0 = 0, time.time()
    while off < len(data):
        r = rpc.call("OTA.Write", {"offset": off, "data": base64.b64encode(data[off:off + CHUNK]).decode()})
        off = r["offset"] if r and "offset" in r else off + CHUNK
        sys.stdout.write(f"\r  {off * 100 // len(data):3d}%  {off}/{len(data)} B")
        sys.stdout.flush()
    print(f"\n  uploaded in {time.time() - t0:.0f}s, device is applying the update")


if __name__ == "__main__":
    main()
