"""Smoke test of a running master server: registers a fake game (heartbeat) and asks for the list.
Usage: python master/smoke_test.py [host] [port] [--v6 host6 [--v6-from addr]] [--limits]
  --v6 host6  also the master's IPv6 address (e.g. ::1): IPv6 game, mixed list (type 32), the IPv4 list unchanged
  --v6-from   the IPv6 browsers' own address (another of the master's machine: the reply must still come from
              host6, not from the address the system would pick)
  --source-warn  only warn if not (Wine 10 ignores the source address of a send)
  --limits    caps and rate limits on IPv6 (and IPv4). Needs a Linux master on this machine and the test prefixes
              bindable here, e.g. as root: ip -6 route add local 2001:db8::/32 dev lo; ip -6 route add local
              fd00:db8::/32 dev lo; ip route add local 198.51.100.0/24 dev lo; sysctl net.ipv6.ip_nonlocal_bind=1
              (master/test_ipv6.sh does all that in a throwaway container)"""
import socket
import struct
import sys
import time

host6 = sys.argv[sys.argv.index("--v6") + 1] if "--v6" in sys.argv else None
v6_from = sys.argv[sys.argv.index("--v6-from") + 1] if "--v6-from" in sys.argv else None
args = [a for a in sys.argv[1:] if not a.startswith("--") and a not in (host6, v6_from)]
host = args[0] if len(args) > 0 else "127.0.0.1"
port = int(args[1]) if len(args) > 1 else 11770
limits = "--limits" in sys.argv
MAGIC, VERSION = 0x424C3248, 16


def header(kind, nonce, version=VERSION):
    return struct.pack("<IBBQ", MAGIC, version, kind, nonce)


info = "Smoke test".encode("utf-16-le").ljust(64, b"\0") + bytes(range(256)) * 2  # opaque to the master
game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
game.sendto(header(8, 0) + info, (host, port))
time.sleep(0.5)

browser = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
browser.settimeout(3)
browser.sendto(header(9, 1234), (host, port))
data, _ = browser.recvfrom(2048)
magic, version, kind, nonce = struct.unpack_from("<IBBQ", data)
count = data[14]
assert (magic, version, kind, nonce) == (MAGIC, VERSION, 10, 1234), (magic, version, kind, nonce)
assert count == 1, count
ip, gport = struct.unpack_from("<4sH", data, 15)
assert data[21:21 + len(info)] == info, "info bytes changed"
assert len(data) == 21 + len(info), "type 10 reply has extra bytes"
print("ok: 1 game listed from %s:%d, %d info bytes kept" % (socket.inet_ntoa(ip), socket.ntohs(gport), len(info)))

# another protocol version sees nothing
other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
other.settimeout(3)
other.sendto(struct.pack("<IBBQ", MAGIC, VERSION + 1, 9, 5), (host, port))
data, _ = other.recvfrom(2048)
assert data[14] == 0, "a different protocol version must not see the game"
print("ok: another protocol version gets an empty list")

# the game closes (unlist): gone from the list at once
game.sendto(header(24, 0), (host, port))
time.sleep(0.5)
browser.sendto(header(9, 1235), (host, port))
data, _ = browser.recvfrom(2048)
assert data[14] == 0, "an unlisted game must leave the list"
print("ok: an unlisted game leaves the list at once")

# --- IPv6 ---------------------------------------------------------------------------------------------------------

def make_info(name, extra=b""):
    return name.encode("utf-16-le")[:64].ljust(64, b"\0") + extra


def ask(sock, dest, version, nonce, flags=None, first=3, wait=0.6):
    """List request (flags byte only if given); returns the reply packets (their source addresses: ask.sources)."""
    ask.sources = set()
    sock.sendto(header(9, nonce, version) + (bytes([flags]) if flags is not None else b""), dest)
    packets, deadline = [], time.time() + 3
    sock.settimeout(first)
    while True:
        try:
            data, src = sock.recvfrom(4096)
        except socket.timeout:
            return packets
        if struct.unpack_from("<Q", data, 6)[0] == nonce:
            ask.sources.add(socket.inet_pton(sock.family, src[0].split("%")[0]))
            packets.append(data)
            sock.settimeout(wait)  # the rest of the list follows right away
        if time.time() > deadline:
            return packets


def entries(packets, info_size=None):
    """Entries of type 10 / type 32 replies: (family, address text, port, info). Type 10 entries carry no info
    size (the game knows its own): info_size."""
    out = []
    for p in packets:
        kind, count, at = p[5], p[14], 15
        for _ in range(count):
            if kind == 10:
                out.append((4, socket.inet_ntoa(p[at:at + 4]), struct.unpack_from("!H", p, at + 4)[0], None))
                at += 6 + info_size
            else:
                assert kind == 32, kind
                family = p[at]
                size = 4 if family == 4 else 16
                assert family in (4, 6), family
                addr = p[at + 1:at + 1 + size]
                gport, isize = struct.unpack_from("!H", p, at + 1 + size)[0], struct.unpack_from("<H", p, at + 3 + size)[0]
                text = socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, addr)
                out.append((family, text, gport, p[at + 5 + size:at + 5 + size + isize]))
                at += 5 + size + isize
        assert at == len(p), "packet size doesn't match its entries"
    return out


def udp6(bind=None):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    if bind or v6_from: s.bind((bind or v6_from, 0))
    return s


def udp4(bind=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if bind: s.bind((bind, 0))
    return s


if host6:
    V = 40
    dest4, dest6 = (host, port), (host6, port)
    info4, info6 = make_info("IPv4 game", bytes(range(256))), make_info("IPv6 game", bytes(range(255, -1, -1)))
    game4, game6 = udp4(), socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    game4.sendto(header(8, 0, V) + info4, dest4)
    game6.sendto(header(8, 0, V) + info6, dest6)
    time.sleep(0.5)
    game6_port = game6.getsockname()[1]

    # the current game's request (no flags byte): the IPv4 list as before, the IPv6 game left out
    old = ask(udp4(), dest4, V, 41)
    assert len(old) == 1 and old[0][5] == 10 and old[0][14] == 1, [p[:15] for p in old]
    assert len(old[0]) == 21 + len(info4) and old[0][21:] == info4
    assert struct.unpack_from("!H", old[0], 19)[0] == game4.getsockname()[1]
    print("ok: current game's list request: type 10, IPv4 game only, %d bytes as before" % len(old[0]))

    # the new browser's request (flags bit 0), from IPv4 and from IPv6: both games
    for name, sock, dest in (("IPv4", udp4(), dest4), ("IPv6", udp6(), dest6)):
        got = entries(ask(sock, dest, V, 42, flags=1))
        fams = sorted((e[0], e[2], e[3]) for e in got)
        assert fams == sorted([(4, game4.getsockname()[1], info4), (6, game6_port, info6)]), got
        print("ok: type 32 list asked over %s: IPv4 + IPv6 game, sizes and info kept" % name)
    try:
        asked = socket.inet_pton(socket.AF_INET6, host6)
    except OSError:
        asked = None  # a host name
    if asked:
        if ask.sources == {asked}:
            print("ok: the IPv6 reply comes from the address asked (%s), not another one of the host's" % host6)
        else:
            got = ", ".join(socket.inet_ntop(socket.AF_INET6, a) for a in ask.sources)
            assert "--source-warn" in sys.argv, "IPv6 reply from %s, not %s (firewalls drop it)" % (got, host6)
            print("WARN: the IPv6 reply comes from %s, not the address asked (%s)" % (got, host6))

    # an IPv6 browser without the flag gets type 10 (IPv4 games only), unknown flag bits are ignored
    got = ask(udp6(), dest6, V, 43)
    assert [p[5] for p in got] == [10] and [e[2] for e in entries(got, len(info4))] == [game4.getsockname()[1]], got
    got = entries(ask(udp6(), dest6, V, 44, flags=0xFF))
    assert len(got) == 2, got
    got = ask(udp6(), dest6, V + 1, 45, flags=1)
    assert len(got) == 1 and got[0][5] == 32 and got[0][14] == 0, got
    print("ok: IPv6 asker without the flag gets type 10; unknown flag bits ignored; other version empty (type 32)")


# --- caps and rate limits (Linux, test prefixes bindable) ---------------------------------------------------------

def register(sources, version, name, dest):
    socks = []
    for src in sources:
        s = udp6(src) if ":" in src else udp4(src)
        s.sendto(header(8, 0, version) + make_info(name), dest)
        socks.append(s)
        time.sleep(0.002)
    time.sleep(0.5)
    return socks


def answered(sources, dest, version, flags=1):
    n = 0
    for i, src in enumerate(sources):
        s = udp6(src) if ":" in src else udp4(src)
        n += bool(ask(s, dest, version, 1000 + i, flags, first=0.5, wait=0.2))
    return n


if limits:
    dest6, dest4 = ("::1", port), ("127.0.0.1", port)
    asker = "2001:db8:ffff::1"
    keep = register(["2001:db8:1:1::%x" % i for i in range(1, 34)], 60, "cap /64", dest6)
    got = entries(ask(udp6(asker), dest6, 60, 1, flags=1))
    assert len(got) == 32, len(got)
    print("ok: 33 IPv6 games from one /64 (different addresses): 32 registered")

    keep += register(["2001:db8:2:%x::%x" % (net, i) for net in range(1, 10) for i in range(1, 33)], 61, "cap /48",
                     dest6)
    got = entries(ask(udp6("2001:db8:ffff::2"), dest6, 61, 2, flags=1))
    assert len(got) == 256, len(got)
    print("ok: 288 IPv6 games from 9 /64s of one /48: 256 registered (one site)")

    keep += register(["198.51.100.7"] * 33, 62, "cap v4", dest4)
    got = entries(ask(udp4("198.51.100.200"), dest4, 62, 3), 64)
    assert len(got) == 32, len(got)
    print("ok: 33 IPv4 games from one address: 32 registered (as before)")

    n = answered(["2001:db8:3:1::%x" % i for i in range(1, 9)], dest6, 63)
    assert n == 6, n
    n = answered(["2001:db8:4:%x::1" % i for i in range(1, 31)], dest6, 63)
    assert n == 24, n
    n = answered(["198.51.100.9"] * 8, dest4, 63, flags=None)
    assert n == 6, n
    print("ok: list requests per 10 s: 6 per IPv6 /64 (8 addresses), 24 per /48 (30 /64s), 6 per IPv4 address")

    keep += register(["fd00:db8::1"], 64, "ULA game", dest6)
    assert entries(ask(udp6("2001:db8:5::1"), dest6, 64, 4, flags=1)) == [], "ULA game listed outside"
    got = entries(ask(udp6("fd00:db8::2"), dest6, 64, 5, flags=1))
    assert [(e[0], e[1]) for e in got] == [(6, "fd00:db8::1")], got
    print("ok: a game on a ULA address is listed to ULA askers only (no NAT on IPv6)")
