#!/usr/bin/env python3
"""Real-kernel end-to-end test of the tunnel (needs root and /dev/net/tun).

Builds nettest.cpp (two network namespaces with TUN devices joined by two LanBridge engines) and runs real TCP, UDP,
ICMP, broadcast and multicast traffic through it. Usage: nettest.py [virtual|alias|android|all]
"""
import hashlib, json, os, random, select, signal, socket, struct, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "app", "src", "main", "cpp")
BIN = os.environ.get("TMPDIR", "/tmp") + "/lanbridge_nettest"
SELF = os.path.abspath(__file__)
PORT = 7777

# ---------------------------------------------------------------- workers (run inside a namespace)

def w_tcp_server(bind, port):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, int(port))); srv.listen(128)
    print("LISTEN", flush=True)
    def handle(c):
        h = hashlib.sha256(); n = 0
        while True:
            d = c.recv(65536)
            if not d: break
            h.update(d); n += len(d)
        try: c.sendall(f"OK {n} {h.hexdigest()}\n".encode())
        except OSError: pass
        c.close()
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

def w_tcp_client(host, port, size, conns, bind=None):
    size = int(size); conns = int(conns); res = []
    def one(i):
        data = random.Random(1000 + i).randbytes(size)
        t0 = time.time()
        s = socket.socket()
        if bind: s.bind((bind, 0))
        s.settimeout(30)
        try:
            s.connect((host, int(port)))
            lip = s.getsockname()[0]; rip = s.getpeername()[0]
            s.sendall(data); s.shutdown(socket.SHUT_WR)
            buf = b""
            while not buf.endswith(b"\n"):
                d = s.recv(1024)
                if not d: break
                buf += d
            ok = buf.decode().strip() == f"OK {size} {hashlib.sha256(data).hexdigest()}"
            res.append((ok, time.time() - t0, lip, rip))
        except Exception as e:
            res.append((False, time.time() - t0, str(e), ""))
        s.close()
    ts = [threading.Thread(target=one, args=(i,)) for i in range(conns)]
    t0 = time.time()
    [t.start() for t in ts]; [t.join() for t in ts]
    el = time.time() - t0
    print(json.dumps({"ok": sum(1 for r in res if r[0]), "of": conns, "sec": round(el, 2),
                      "mbps": round(size * conns * 8 / el / 1e6, 2), "src": res[0][2] if res else "", "dst": res[0][3] if res else ""}))

def w_udp_echo_server(bind, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, int(port)))
    print("LISTEN", flush=True)
    while True:
        d, a = s.recvfrom(70000)
        s.sendto(d, a)

def w_udp_client(host, port, sizes, count, connected, bind=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.4)
    if bind: s.bind((bind, 0))
    if connected == "1": s.connect((host, int(port)))
    out = {}
    for size in [int(x) for x in sizes.split(",")]:
        lost = bad = 0
        for i in range(int(count)):
            payload = random.Random(size * 7919 + i).randbytes(size)
            try:
                if connected == "1": s.send(payload)
                else: s.sendto(payload, (host, int(port)))
                got = None
                while True:
                    d, a = s.recvfrom(70000) if connected != "1" else (s.recv(70000), None)
                    got = d; break
                if got != payload: bad += 1
                elif a is not None and a[0] != host: bad += 1
            except socket.timeout:
                lost += 1
        out[size] = {"lost": lost, "bad": bad}
    print(json.dumps(out))

def w_udp_burst_recv(port, secs):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    s.bind(("0.0.0.0", int(port))); s.settimeout(1.0)
    print("LISTEN", flush=True)
    seen = set(); end = time.time() + float(secs); last = time.time()
    while time.time() < end:
        try:
            d, _ = s.recvfrom(70000); seen.add(struct.unpack("!I", d[:4])[0]); last = time.time()
        except socket.timeout:
            if seen and time.time() - last > 2: break
    print(json.dumps({"got": len(seen)}))

def w_udp_burst_send(host, port, count, size, per_ms="0"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 << 20)
    pad = b"x" * (int(size) - 4)
    per_ms = float(per_ms)
    t0 = time.time()
    for i in range(int(count)):
        try: s.sendto(struct.pack("!I", i) + pad, (host, int(port)))
        except OSError: pass
        if per_ms and i % 10 == 9:
            while (time.time() - t0) * 1000 * per_ms < i: time.sleep(0.0005)
    print(json.dumps({"sent": int(count), "sec": round(time.time() - t0, 2)}))

def w_bcast_recv(port, secs, bind="0.0.0.0"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.bind((bind, int(port))); s.settimeout(float(secs))
    print("LISTEN", flush=True)
    try:
        d, a = s.recvfrom(2000); print(json.dumps({"got": d.decode(), "from": a[0]}))
    except socket.timeout:
        print(json.dumps({"got": None}))

def w_bcast_send(dst, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for _ in range(3):
        s.sendto(b"hello-bcast", (dst, int(port))); time.sleep(0.2)
    print(json.dumps({"sent": 3}))

def w_mcast_recv(group, port, ifaddr, secs):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(port)))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(group) + socket.inet_aton(ifaddr))
    s.settimeout(float(secs)); print("LISTEN", flush=True)
    try:
        d, a = s.recvfrom(2000); print(json.dumps({"got": d.decode(), "from": a[0]}))
    except socket.timeout:
        print(json.dumps({"got": None}))

def w_mcast_send(group, port, ifaddr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ifaddr))
    for _ in range(3):
        s.sendto(b"hello-mcast", (group, int(port))); time.sleep(0.2)
    print(json.dumps({"sent": 3}))

def w_ping(host, count):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); s.settimeout(1.0)
    ident = os.getpid() & 0xFFFF; ok = 0; rtts = []
    def csum(b):
        if len(b) % 2: b += b"\0"
        t = sum(struct.unpack("!%dH" % (len(b) // 2), b)); t = (t >> 16) + (t & 0xFFFF); t += t >> 16
        return ~t & 0xFFFF
    for seq in range(int(count)):
        pl = b"lanbridge-ping-" + bytes(range(40))
        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
        pkt = struct.pack("!BBHHH", 8, 0, csum(hdr + pl), ident, seq) + pl
        t0 = time.time(); s.sendto(pkt, (host, 0))
        try:
            while True:
                d, a = s.recvfrom(2000); ihl = (d[0] & 15) * 4
                if d[ihl] == 0 and struct.unpack("!HH", d[ihl + 4:ihl + 8]) == (ident, seq) and d[ihl + 8:] == pl:
                    ok += 1; rtts.append((time.time() - t0) * 1000); break
        except socket.timeout:
            pass
    print(json.dumps({"ok": ok, "of": int(count), "rtt_ms": round(sum(rtts) / len(rtts), 1) if rtts else None}))

# ---------------------------------------------------------------- driver

class Env:
    def __init__(self, mode, mtu=1500):
        self.mode = mode
        args = {"virtual": [], "alias": ["alias"], "android": ["alias", "android"]}[mode]
        self.p = subprocess.Popen([BIN] + args, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  env=dict(os.environ, NETTEST_MTU=str(mtu)))
        line = ""
        t0 = time.time()
        while time.time() - t0 < 20:
            line = self.p.stdout.readline()
            if line.startswith("READY") or not line: break
        if not line.startswith("READY"):
            err = self.p.stderr.read() if self.p.poll() is not None else ""
            raise RuntimeError("nettest did not come up: " + line + err)
        f = line.split()
        self.pid = {"A": f[1], "B": f[2]}
        self.vip = {"A": f[3], "B": f[4]}
        self.info = {"A": self.p.stdout.readline().strip(), "B": self.p.stdout.readline().strip()}
        self.real = {"A": "192.168.1.5", "B": "10.20.30.7"} if mode in ("alias", "android") else {}

    def cmd(self, side, *args):
        return ["nsenter", "-t", self.pid[side], "-n", sys.executable, SELF, "--worker"] + [str(a) for a in args]

    def run(self, side, *args, timeout=120):
        r = subprocess.run(self.cmd(side, *args), capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0: return {"error": (r.stderr or r.stdout)[-300:]}
        try: return json.loads(r.stdout.strip().splitlines()[-1])
        except Exception: return {"error": "bad output: " + r.stdout[-200:]}

    def start_server(self, side, *args):
        p = subprocess.Popen(self.cmd(side, *args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        l = p.stdout.readline()
        if "LISTEN" not in l: raise RuntimeError("server failed: " + p.stderr.read())
        return p

    def close(self):
        try: self.p.stdin.close()
        except Exception: pass
        out = ""
        try: out = self.p.stdout.read()
        except Exception: pass
        try: self.p.wait(timeout=10)
        except Exception: self.p.kill()
        return out

results = []
def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("  ok   " if cond else "  FAIL ") + name + (("   " + str(detail)) if detail != "" else ""), flush=True)

def sv(proc):
    if proc: proc.kill(); proc.wait()

def suite_common(env, tag, dstB, dstA, bindB=None):
    """dstB: address of B as seen from A (virtual or mirrored real), dstA likewise."""
    # ICMP
    r = env.run("A", "ping", dstB, 5); check(f"{tag} ping A->B", r.get("ok") == 5, r)
    r = env.run("B", "ping", dstA, 5); check(f"{tag} ping B->A", r.get("ok") == 5, r)
    # TCP bulk, both directions
    s = env.start_server("B", "tcp_server", bindB or "0.0.0.0", PORT)
    r = env.run("A", "tcp_client", dstB, PORT, 8 << 20, 1); check(f"{tag} tcp 8 MB A->B", r.get("ok") == 1, r)
    r = env.run("A", "tcp_client", dstB, PORT, 256 << 10, 20); check(f"{tag} tcp 20 x 256 KB parallel", r.get("ok") == 20, r)
    sv(s)
    s = env.start_server("A", "tcp_server", "0.0.0.0", PORT)
    r = env.run("B", "tcp_client", dstA, PORT, 4 << 20, 1); check(f"{tag} tcp 4 MB B->A", r.get("ok") == 1, r)
    sv(s)
    # UDP echo: small, MTU-sized, fragmented
    sizes = "32,512,1200,1400,1472,3000,9000,30000,60000"
    s = env.start_server("B", "udp_echo_server", bindB or "0.0.0.0", PORT)
    r = env.run("A", "udp_client", dstB, PORT, sizes, 25, 0)
    check(f"{tag} udp echo (unconnected) all sizes", all(v["lost"] == 0 and v["bad"] == 0 for v in r.values()) if "error" not in r else False, r)
    r = env.run("A", "udp_client", dstB, PORT, "32,1200,1472,4000,9000", 12, 1)
    check(f"{tag} udp echo (connected socket: reply source must match)", all(v["lost"] == 0 and v["bad"] == 0 for v in r.values()) if "error" not in r else False, r)
    sv(s)
    # UDP at a realistic pace (about 12 Mbit/s for 4 s) and an unpaced blast (informational)
    s = env.start_server("B", "udp_burst_recv", PORT, 25)
    r1 = env.run("A", "udp_burst_send", dstB, PORT, 5000, 1200, 1.25)
    time.sleep(0.5)
    got = json.loads(s.communicate(timeout=40)[0].strip().splitlines()[-1])["got"]
    check(f"{tag} udp paced 5000 x 1200 B (12 Mbit/s) delivered >= 99%", got >= 4950, f"{got}/5000 in {r1.get('sec')} s")
    s = env.start_server("B", "udp_burst_recv", PORT, 25)
    r1 = env.run("A", "udp_burst_send", dstB, PORT, 400, 1200)
    time.sleep(0.5)
    got = json.loads(s.communicate(timeout=40)[0].strip().splitlines()[-1])["got"]
    check(f"{tag} udp blast of 400 packets (a 480 KB snapshot) delivered >= 98%", got >= 392, f"{got}/400 in {r1.get('sec')} s")

def suite_virtual_only(env):
    vb, va = env.vip["B"], env.vip["A"]
    net = vb.rsplit(".", 1)[0]
    # broadcast / multicast
    for dst, label in (("255.255.255.255", "limited broadcast"), (net + ".255", "directed broadcast")):
        s = env.start_server("B", "bcast_recv", 9999, 6)
        env.run("A", "bcast_send", dst, 9999)
        out = json.loads(s.communicate(timeout=20)[0].strip().splitlines()[-1])
        check(f"virtual {label}", out.get("got") == "hello-bcast", out)
    s = env.start_server("B", "mcast_recv", "239.255.77.77", 9998, vb, 6)
    env.run("A", "mcast_send", "239.255.77.77", 9998, va)
    out = json.loads(s.communicate(timeout=20)[0].strip().splitlines()[-1])
    check("virtual multicast", out.get("got") == "hello-mcast", out)

def suite_alias(env):
    ra, rb = env.real["A"], env.real["B"]
    # the virtual addresses keep working next to the mirrored real ones
    suite_common(env, "alias+virtual", env.vip["B"], env.vip["A"])
    # to the real address, as a game that advertises its Wi-Fi address would do
    suite_common(env, "alias", rb, ra)
    # a server bound ONLY to its real address (a game that binds to the Wi-Fi address)
    s = env.start_server("B", "tcp_server", rb, PORT)
    r = env.run("A", "tcp_client", rb, PORT, 1 << 20, 1)
    check("alias tcp to a server bound only to the real address", r.get("ok") == 1 and r.get("src") == ra and r.get("dst") == rb, r)
    sv(s)
    s = env.start_server("B", "udp_echo_server", rb, PORT)
    r = env.run("A", "udp_client", rb, PORT, "100,1400,4000", 10, 1)
    check("alias udp (connected) to a server bound only to the real address", all(v["lost"] == 0 and v["bad"] == 0 for v in r.values()) if "error" not in r else False, r)
    sv(s)
    # a client bound to its real address talking to the virtual address of the friend
    s = env.start_server("B", "tcp_server", "0.0.0.0", PORT)
    r = env.run("A", "tcp_client", env.vip["B"], PORT, 1 << 20, 1, ra)
    check("alias tcp from a socket bound to the real address to the virtual address", r.get("ok") == 1, r)
    sv(s)
    # broadcast with the real address as source: the reply must come back to it
    s = env.start_server("B", "bcast_recv", 9999, 6, "0.0.0.0")
    env.run("A", "bcast_send", "255.255.255.255", 9999)
    out = json.loads(s.communicate(timeout=20)[0].strip().splitlines()[-1])
    check("alias broadcast delivered", out.get("got") == "hello-bcast", out)
    check("alias broadcast source is the real address", out.get("from") == ra, out)

def suite_android(env):
    """Android-like routing: the first (real) address is the source of everything that leaves through the TUN."""
    ra, rb = env.real["A"], env.real["B"]
    for tag, dstB, dstA in (("android virtual dst", env.vip["B"], env.vip["A"]), ("android real dst", rb, ra)):
        s = env.start_server("B", "udp_echo_server", "0.0.0.0", PORT)
        r = env.run("A", "udp_client", dstB, PORT, "32,1200,1472,4000,30000", 15, 0)
        check(f"{tag}: udp echo, reply source must equal the address that was used",
              all(v["lost"] == 0 and v["bad"] == 0 for v in r.values()) if "error" not in r else False, r)
        r = env.run("A", "udp_client", dstB, PORT, "32,1200,4000", 15, 1)
        check(f"{tag}: udp echo through a connected socket",
              all(v["lost"] == 0 and v["bad"] == 0 for v in r.values()) if "error" not in r else False, r)
        sv(s)
        s = env.start_server("A", "udp_echo_server", "0.0.0.0", PORT)
        r = env.run("B", "udp_client", dstA, PORT, "32,1200,4000", 15, 1)
        check(f"{tag}: udp echo B->A through a connected socket",
              all(v["lost"] == 0 and v["bad"] == 0 for v in r.values()) if "error" not in r else False, r)
        sv(s)
        s = env.start_server("B", "tcp_server", "0.0.0.0", PORT)
        r = env.run("A", "tcp_client", dstB, PORT, 2 << 20, 3); check(f"{tag}: tcp 3 x 2 MB", r.get("ok") == 3, r)
        sv(s)
    suite_common(env, "android", env.vip["B"], env.vip["A"])


def run_mode(mode, mtu=1500):
    import re
    print(f"== {mode}, TUN MTU {mtu} ==", flush=True)
    env = Env(mode, mtu)
    print("  " + env.info["A"][:160], flush=True); print("  " + env.info["B"][:160], flush=True)
    try:
        if mode == "virtual":
            suite_common(env, "virtual", env.vip["B"], env.vip["A"])
            suite_virtual_only(env)
        elif mode == "alias":
            suite_alias(env)
        else:
            suite_android(env)
    finally:
        out = env.close()
        for l in out.splitlines():
            if l.startswith(("STATS", "FLOWS")): print("  " + l[:400])
    # with MTU 1500 the big UDP datagrams must have been cut into chunks by the tunnel (never by the network)
    cut = [int(m.group(1)) for m in re.finditer(r"разбито туннелем: (\d+)", out)]
    joined = [int(m.group(1)) for m in re.finditer(r"собрано: (\d+)", out)]
    lost = [int(m.group(1)) for m in re.finditer(r"не собрано за 3 с: (\d+)", out)]
    if mtu > 1339 + 28 - 1:
        check(f"{mode} MTU {mtu}: tunnel cut and reassembled big packets", len(cut) == 2 and min(cut) > 0 and min(joined) > 0, f"cut={cut} joined={joined}")
        check(f"{mode} MTU {mtu}: no chunk was lost", lost == [0, 0], lost)
        mss = [int(m.group(1)) for m in re.finditer(r"MSS урезан в (\d+)", out)]
        check(f"{mode} MTU {mtu}: TCP SYNs got their MSS capped on both sides", len(mss) == 2 and min(mss) > 0, mss)
    else:
        check(f"{mode} MTU {mtu}: small MTU needs no chunks", cut == [0, 0], cut)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        globals()["w_" + sys.argv[2]](*sys.argv[3:]); return
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if os.geteuid() != 0 or not os.path.exists("/dev/net/tun"):
        print("nettest skipped: needs root and /dev/net/tun"); return
    sources = [os.path.join(SRC, f) for f in ("util.cpp", "crypto.cpp", "offer.cpp", "stun.cpp", "protocol.cpp", "ipv6.cpp", "frag.cpp", "engine.cpp")]
    r = subprocess.run(["g++", "-std=c++17", "-O1", "-g", "-Wall", "-Wextra", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined",
                        "-pthread", "-I" + SRC, os.path.join(HERE, "nettest.cpp")] + sources + ["-o", BIN], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr); sys.exit(2)
    jobs = [("virtual", 1500), ("alias", 1500), ("android", 1500), ("virtual", 1280)] if mode == "all" else [(mode, int(os.environ.get("NETTEST_MTU", "1500")))]
    for m, mtu in jobs:
        run_mode(m, mtu)
    bad = [n for n, ok in results if not ok]
    print(f"\nnettest: {len(results) - len(bad)} passed, {len(bad)} failed")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
