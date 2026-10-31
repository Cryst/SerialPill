#!/usr/bin/env python3
"""SerialPill command line client (Python standard library only).

  spctl.py <host> setup                     create the administrator (first use)
  spctl.py <host> status | config | users | log
  spctl.py <host> set '<json>'              e.g. set '{"serial":{"baud":115200}}'
  spctl.py <host> firmware <SerialPill-ota.bin>
  spctl.py <host> key <user> <pubkey-file>
  spctl.py <host> send '<text>'             write to the UART (\\r, \\n escapes allowed)
  spctl.py <host> read [seconds]            print UART output
  spctl.py <host> shelly-restore stable|beta | shelly-upload <Pill-x.zip>

Credentials: --user/--password, or the SERIALPILL_USER / SERIALPILL_PASSWORD environment
variables, or a JSON file given with --credentials ({"user": .., "password": ..}).
Use --https for devices with an installed certificate (add --insecure for self-signed ones).
"""
import argparse
import base64
import http.client
import json
import os
import ssl
import sys
import time


class Client:
    def __init__(self, host, https=False, insecure=False):
        self.host, self.https = host, https
        self.ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        self.cookie = None

    def req(self, method, path, body=None, ctype="application/json", timeout=60):
        c = (http.client.HTTPSConnection(self.host, timeout=timeout, context=self.ctx) if self.https
             else http.client.HTTPConnection(self.host, timeout=timeout))
        h = {"X-Requested-With": "SerialPill"}
        if self.cookie:
            h["Cookie"] = self.cookie
        if body is not None and not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body).encode()
        if body is not None:
            h["Content-Type"] = ctype
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        sc = r.getheader("Set-Cookie")
        if sc and sc.startswith("sp_sid="):
            self.cookie = sc.split(";")[0]
        try:
            j = json.loads(data) if data else {}
        except ValueError:
            j = {"raw": data.decode(errors="replace")}
        if r.status >= 400:
            raise SystemExit(f"{method} {path}: HTTP {r.status} {j.get('error', j)}")
        return j

    def login(self, user, password):
        self.req("POST", "/api/login", {"user": user, "password": password})


def creds(a):
    if a.credentials:
        c = json.load(open(a.credentials))
        return c["user"], c["password"]
    u = a.user or os.environ.get("SERIALPILL_USER", "admin")
    p = a.password or os.environ.get("SERIALPILL_PASSWORD")
    if not p:
        import getpass
        p = getpass.getpass(f"password for {u}: ")
    return u, p


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("cmd")
    ap.add_argument("args", nargs="*")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--credentials")
    ap.add_argument("--https", action="store_true")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    c = Client(a.host, a.https, a.insecure)
    user, pw = creds(a)
    if a.cmd == "setup":
        c.req("POST", "/api/setup", {"user": user, "password": pw})
        print("administrator created")
        return
    c.login(user, pw)
    out = None
    if a.cmd in ("status", "config", "users", "log"):
        out = c.req("GET", "/api/" + a.cmd)
    elif a.cmd == "set":
        out = c.req("POST", "/api/config", json.loads(a.args[0]))
    elif a.cmd == "firmware":
        data = open(a.args[0], "rb").read()
        c.req("POST", "/api/firmware", data, "application/octet-stream", timeout=300)
        print(f"uploaded {len(data)} B, device reboots")
    elif a.cmd == "key":
        out = c.req("POST", "/api/keys", {"user": a.args[0], "key": open(a.args[1]).read().strip()})
    elif a.cmd == "send":
        text = a.args[0].encode().decode("unicode_escape").encode("latin-1")
        out = c.req("POST", "/api/term", text, "application/octet-stream")
    elif a.cmd == "read":
        end = time.time() + float(a.args[0] if a.args else 3)
        seq = c.req("GET", "/api/term")["seq"]
        while time.time() < end:
            j = c.req("GET", f"/api/term?since={seq}")
            sys.stdout.buffer.write(base64.b64decode(j["d"]))
            sys.stdout.flush()
            seq = j["seq"]
            time.sleep(0.2)
    elif a.cmd == "shelly-restore":
        out = c.req("POST", "/api/shelly/restore?channel=" + (a.args[0] if a.args else "stable"))
    elif a.cmd == "shelly-upload":
        data = open(a.args[0], "rb").read()
        out = c.req("POST", "/api/shelly/upload", data, "application/zip", timeout=600)
    else:
        raise SystemExit(f"unknown command {a.cmd}")
    if out is not None:
        print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
