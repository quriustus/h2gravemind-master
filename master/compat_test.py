"""The current game must not notice the IPv6 change: runs the master before it (old) and after it (new, dual-stack
and --ipv4-only) side by side, registers the same IPv4 games in all from the same sockets (plus IPv6 games in the
new ones), and compares every list reply the current game can get, byte for byte.
Usage: python3 master/compat_test.py <old master binary> <new master binary>
Linux, with the test prefixes bindable (see smoke_test.py --limits; master/test_ipv6.sh sets them up)."""
import socket
import struct
import subprocess
import sys
import time

old_bin, new_bin = sys.argv[1], sys.argv[2]
MAGIC = 0x424C3248
PUBLIC = "203.0.113.5"
masters = {  # name -> (command, port)
    "old": ([old_bin], 11871),
    "new": ([new_bin], 11872),
    "new --ipv4-only": ([new_bin, "--ipv4-only"], 11873),
    "old --public-ip": ([old_bin, "--public-ip", PUBLIC], 11874),
    "new --public-ip": ([new_bin, "--public-ip", PUBLIC], 11875),
}
procs = [subprocess.Popen(cmd + ["--port", str(port)], stdout=subprocess.DEVNULL) for cmd, port in masters.values()]
time.sleep(0.5)


def header(kind, nonce, version):
    return struct.pack("<IBBQ", MAGIC, version, kind, nonce)


def info(name, size):
    return (name.encode("utf-16-le").ljust(64, b"\0") + bytes(i * 7 % 256 for i in range(size)))[:size]


try:
    # IPv4 games: loopback, private (10.x, the master's network: --public-ip rewrites them for outside askers) and
    # public sources; several per address; protocol versions 16 and 17; info sizes from the minimum to the maximum
    games = [("127.0.0.2", 16, 16), ("127.0.0.2", 16, 576), ("127.0.0.3", 16, 1451), ("10.99.0.1", 16, 300),
             ("10.99.0.1", 16, 800), ("198.51.100.1", 16, 700), ("198.51.100.2", 16, 64), ("198.51.100.2", 17, 576),
             ("10.99.0.2", 16, 1000), ("198.51.100.3", 16, 1451), ("127.0.0.4", 17, 200)]
    socks = []
    for i, (src, version, size) in enumerate(games):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((src, 0))
        socks.append(s)
        for _, port in masters.values():
            s.sendto(header(8, 0, version) + info("game %d" % i, size), ("127.0.0.1", port))
    # IPv6 games, which the new masters also take: they must not change the IPv4 list
    for src, version in (("2001:db8:1::1", 16), ("2001:db8:1::2", 17), ("fd00:db8::1", 16), ("::1", 16)):
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind((src, 0))
        socks.append(s)
        for name, (_, port) in masters.items():
            if name.startswith("new") and "ipv4-only" not in name:
                s.sendto(header(8, 0, version) + info("v6 game", 600), ("::1", port))
    time.sleep(0.5)

    def replies(port, asker, version, nonce):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((asker, 0))
        s.sendto(header(9, nonce, version), ("127.0.0.1", port))
        s.settimeout(2)
        out = []
        try:
            while True:
                out.append(s.recvfrom(4096)[0])
                s.settimeout(0.3)
        except socket.timeout:
            return out

    checked = 0
    for asker in ("127.0.0.1", "10.99.0.50", "198.51.100.200"):  # loopback, private and outside browsers
        for version in (16, 17, 99):
            nonce = 0x1122334455667700 + version
            for pair in (("old", "new", "new --ipv4-only"), ("old --public-ip", "new --public-ip")):
                got = {name: replies(masters[name][1], asker, version, nonce) for name in pair}
                ref = got[pair[0]]
                assert ref, (asker, version, "no reply")
                for name in pair[1:]:
                    assert got[name] == ref, "%s differs from %s: asker %s version %d\n%r\n%r" % (
                        name, pair[0], asker, version, [p[:24] for p in got[name]], [p[:24] for p in ref])
                checked += 1
                print("ok: asker %-15s protocol %-3d %-36s %d packets, %4d bytes, %d games: identical" % (
                    asker, version, " = ".join(pair), len(ref), sum(map(len, ref)), sum(p[14] for p in ref)))
    print("ok: %d list replies byte for byte identical (current game's request; IPv6 games registered too)" % checked)
finally:
    for p in procs:
        p.terminate()
