"""Hardware test (run: python test/newline_matrix.py test/.credentials). Exact byte matrix for SerialPill line endings.

For every input channel (SSH, telnet, WebSocket, USB-C COM, HTTP API) and every Enter mode
(raw, cr, lf, crlf) the bytes arriving at the far end of the UART are compared exactly.
Then device output (bare LF, CRLF, CR) is injected at the far end and compared exactly in every
channel, with out_crlf off and on.

Far end: Pill .198 with the SerialPill Script edition, crossover cable, 9600 8N1.
"""
import base64, http.client, json, socket, sys, time
import paramiko, serial, websocket

H, FAR = "192.168.37.199", "192.168.37.198"
CR = json.load(open(sys.argv[1]))
results = []


def check(name, got, want):
    ok = got == want
    results.append(ok)
    print(f"{'OK  ' if ok else 'FAIL'} {name:58s} {'' if ok else f'got {got!r} want {want!r}'}", flush=True)


# ---------------------------------------------------------------- SerialPill API
def api(method, path, body=None):
    c = http.client.HTTPConnection(H, timeout=20)
    c.request("POST", "/api/login", json.dumps(CR), {"Content-Type": "application/json"})
    r = c.getresponse(); r.read()
    ck = r.getheader("Set-Cookie").split(";")[0]
    h = {"Cookie": ck, "X-Requested-With": "SerialPill"}
    if body is not None and not isinstance(body, bytes):
        body = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    c.request(method, path, body, h)
    r = c.getresponse(); d = r.read()
    return ck, json.loads(d) if d else {}


def set_serial(**kw):
    api("POST", "/api/config", {"serial": kw})
    time.sleep(0.3)


# ---------------------------------------------------------------- far end (Script edition)
def far_seq():
    return json.load(_far("GET", "/script/1/term"))["seq"]


def _far(m, p, b=None):
    c = http.client.HTTPConnection(FAR, timeout=10)
    c.request(m, p, b)
    return c.getresponse()


def far_read(since, settle=1.5):
    out, end = b"", time.time() + settle
    while time.time() < end:
        j = json.load(_far("GET", f"/script/1/term?since={since}"))
        d = base64.b64decode(j["d"])
        if d: out += d; since = j["seq"]; end = time.time() + 0.6
        time.sleep(0.15)
    return out


def far_send(data):
    _far("POST", "/script/1/term?b64=1", base64.b64encode(data)).read()


# ---------------------------------------------------------------- channels (persistent)
class Ssh:
    name = "ssh"
    def __init__(self):
        self.c = paramiko.SSHClient(); self.c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.c.connect(H, username=CR["user"], password=CR["password"], look_for_keys=False, allow_agent=False, timeout=20)
        self.ch = self.c.invoke_shell(); time.sleep(1); self.drain()
    def send(self, d): self.ch.send(d)
    def drain(self, t=0.3):
        out, end = b"", time.time() + t
        while time.time() < end:
            if self.ch.recv_ready(): out += self.ch.recv(65536); end = time.time() + 0.4
            else: time.sleep(0.05)
        return out
    def close(self): self.c.close()


class Telnet:
    name = "telnet"
    def __init__(self):
        self.s = socket.create_connection((H, 23), 5); self.s.settimeout(0.2)
        self.drain(1); self.s.send(b"admin\r\n"); self.drain(1)
        self.s.send(CR["password"].encode() + b"\r\n"); self.drain(4)
    def send(self, d): self.s.send(d)
    def drain(self, t=0.3):
        out, end = b"", time.time() + t
        while time.time() < end:
            try:
                d = self.s.recv(65536)
                if not d: break
                out += d; end = time.time() + 0.4
            except socket.timeout: pass
        return out
    def close(self): self.s.close()


class Ws:
    name = "websocket"
    def __init__(self):
        ck, _ = api("GET", "/api/whoami")
        self.w = websocket.create_connection(f"ws://{H}/api/ws", cookie=ck, origin=f"http://{H}", timeout=0.3)
        self.drain(0.5)
    def send(self, d): self.w.send_binary(d)
    def drain(self, t=0.3):
        out, end = b"", time.time() + t
        while time.time() < end:
            try: out += self.w.recv(); end = time.time() + 0.4
            except websocket.WebSocketTimeoutException: pass
        return out
    def close(self): self.w.close()


class Usb:
    name = "usb-c"
    def __init__(self):
        self.p = serial.Serial(); self.p.port = "COM9"; self.p.baudrate = 115200; self.p.timeout = 0.1
        self.p.dtr = False; self.p.rts = False; self.p.open(); time.sleep(0.5); self.drain()
    def send(self, d): self.p.write(d)
    def drain(self, t=0.3):
        out, end = b"", time.time() + t
        while time.time() < end:
            d = self.p.read(65536)
            if d: out += d; end = time.time() + 0.4
        return out
    def close(self): self.p.close()


# ---------------------------------------------------------------- input matrix
# what a client sends for "a<Enter>b" in its different styles
STYLES = {"CR": b"a\rb", "CRLF": b"a\r\nb", "LF": b"a\nb", "CR NUL": b"a\r\x00b", "2 Enters CRLF": b"x\r\n\r\ny"}
EXPECT = {
    "raw":  {"CR": b"a\rb", "CRLF": b"a\r\nb", "LF": b"a\nb", "CR NUL": b"a\r\x00b", "2 Enters CRLF": b"x\r\n\r\ny"},
    "cr":   {"CR": b"a\rb", "CRLF": b"a\rb", "LF": b"a\rb", "CR NUL": b"a\rb", "2 Enters CRLF": b"x\r\ry"},
    "lf":   {"CR": b"a\nb", "CRLF": b"a\nb", "LF": b"a\nb", "CR NUL": b"a\nb", "2 Enters CRLF": b"x\n\ny"},
    "crlf": {"CR": b"a\r\nb", "CRLF": b"a\r\nb", "LF": b"a\r\nb", "CR NUL": b"a\r\nb", "2 Enters CRLF": b"x\r\n\r\ny"},
}
# telnet is a protocol with its own end-of-line rules: CR LF and CR NUL both mean CR (RFC 854),
# so in raw mode a telnet client's line ending reaches the device as CR
TELNET_RAW = {"CR": b"a\rb", "CRLF": b"a\rb", "LF": b"a\nb", "CR NUL": b"a\rb", "2 Enters CRLF": b"x\r\ry"}

set_serial(enter="raw", out_crlf=False)
# local echo off: these checks compare exact bytes, echoed input would mix into the device output
api("POST", "/api/config", {"access": {"telnet_en": True, "echo": False}})
time.sleep(1)
chans = [Ssh(), Telnet(), Ws(), Usb()]

print("=== input: client -> UART (exact bytes at the far end)")
for mode in ("raw", "cr", "lf", "crlf"):
    set_serial(enter=mode)
    for ch in chans:
        for style, data in STYLES.items():
            want = EXPECT[mode][style]
            if ch.name == "telnet" and mode == "raw": want = TELNET_RAW[style]
            s0 = far_seq(); ch.send(data); got = far_read(s0)
            check(f"{ch.name:9s} enter={mode:4s} client sends {style}", got, want)
            ch.drain(0.1)

# HTTP API is programmatic: never translated
set_serial(enter="crlf")
s0 = far_seq(); api("POST", "/api/term", b"a\rb\nc"); got = far_read(s0)
check("http-api  enter=crlf raw passthrough", got, b"a\rb\nc")

print("=== output: UART -> client (exact bytes in each channel)")
OUT = b"line1\r\nline2\nline3\rend"
for oc in (False, True):
    set_serial(enter="raw", out_crlf=oc)
    want = b"line1\r\nline2\r\nline3\rend" if oc else OUT
    for ch in chans: ch.drain(0.2)
    far_send(OUT); time.sleep(1.5)
    for ch in chans:
        check(f"{ch.name:9s} out_crlf={oc!s:5s} device sends CRLF/LF/CR", ch.drain(1.5), want)
    # history/API always raw
    ck, j = api("GET", "/api/term?since=0")
    hist = base64.b64decode(j["d"])
    check(f"http-api  out_crlf={oc!s:5s} history raw", hist[-len(OUT):], OUT)

print("=== transparency (enter=raw): all byte values except Ctrl+] (escape), Ctrl+] Ctrl+] = literal")
set_serial(enter="raw", out_crlf=False)
data = bytes(b for b in range(256) if b != 0x1D)
for ch in chans:
    if ch.name == "telnet":
        sent = data.replace(b"\xff", b"\xff\xff")           # IAC must be doubled by the client
        want = data.replace(b"\r\x00", b"\r")                # no CR NUL pair in this sequence
    else:
        sent, want = data, data
    s0 = far_seq(); ch.send(sent); got = far_read(s0, 3)
    check(f"{ch.name:9s} 255 byte values client -> UART", got, want)
    s0 = far_seq(); ch.send(b"\x1d\x1d"); got = far_read(s0)
    check(f"{ch.name:9s} Ctrl+] Ctrl+] -> literal 0x1d", got, b"\x1d")
far_send(data); time.sleep(2)
for ch in chans:
    got = ch.drain(2)
    if ch.name == "telnet": got = got.replace(b"\xff\xff", b"\xff")
    check(f"{ch.name:9s} 255 byte values UART -> client", got, data)

for ch in chans: ch.close()
set_serial(enter="raw", out_crlf=False)
api("POST", "/api/config", {"access": {"telnet_en": False, "echo": True}})
print(f"\n{sum(results)}/{len(results)} checks passed")
