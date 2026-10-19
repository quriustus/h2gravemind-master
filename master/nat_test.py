"""NAT traversal (rendezvous) test of a running master: introductions (types 40, 41, 42) and the host's own public
address (46).
Usage: python3 master/nat_test.py [host] [port] [--v6 host6 [--v6-from addr]] [--public-ip a.b.c.d] [--limits]
  --v6 host6     also IPv6: introductions over IPv6, replies and introductions from the address the other side wrote to
  --v6-from      the players' own IPv6 address (another of the master's machine)
  --public-ip    the master runs with this --public-ip: a game on its network is introduced by that address
  --limits       per source (/64, /48) and per game limits. Needs the test prefixes bindable on this machine (see
                 smoke_test.py --limits; master/test_ipv6.sh sets them up in a throwaway container)"""
import socket
import struct
import sys
import time

def opt(name):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else None

host6, v6_from, public_ip = opt("--v6"), opt("--v6-from"), opt("--public-ip")
args = [a for a in sys.argv[1:] if not a.startswith("--") and a not in (host6, v6_from, public_ip)]
host = args[0] if len(args) > 0 else "127.0.0.1"
port = int(args[1]) if len(args) > 1 else 11770
limits = "--limits" in sys.argv
MAGIC = 0x424C3248
checks = 0


def ok(text):
    global checks
    checks += 1
    print("ok: " + text)


def header(kind, nonce, version):
    return struct.pack("<IBBQ", MAGIC, version, kind, nonce)


def entry(family, addr, gport):
    raw = socket.inet_pton(socket.AF_INET if family == 4 else socket.AF_INET6, addr)
    return bytes([family]) + raw + struct.pack("!H", gport)


def read_entry(data, at):
    family = data[at]
    size = 4 if family == 4 else 16
    addr = socket.inet_ntop(socket.AF_INET if family == 4 else socket.AF_INET6, data[at + 1:at + 1 + size])
    return family, addr, struct.unpack_from("!H", data, at + 1 + size)[0], at + 3 + size


def intro_request(nonce, version, family, addr, gport, size=128, padding=b""):
    body = header(40, nonce, version) + b"\0" + entry(family, addr, gport) + padding
    return (body + b"\0" * size)[:size]


def info(name):
    return name.encode("utf-16-le").ljust(64, b"\0") + bytes(range(200))


def drain(sock, wait=0.4):
    """Every packet that arrives within `wait` seconds of the last one: [(data, source address)]"""
    out = []
    sock.settimeout(wait)
    try:
        while True:
            data, src = sock.recvfrom(4096)
            out.append((data, src[0].split("%")[0]))
    except socket.timeout:
        return out


def udp(family, bind=None):
    s = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind((bind or ("0.0.0.0" if family == 4 else (v6_from or "::")), 0))
    return s


def own(sock):
    """The address the master sees for sock (loopback tests: the bound one)"""
    name = sock.getsockname()
    return name[0], name[1]


def register(sock, version, name, dest):
    sock.sendto(header(8, 0, version) + info(name), dest)


def check_flow(fam, dest, master_addr, version, label):
    """A game registers, a player asks for an introduction: the game gets 41 with the player's address and nonce, the
    player 42 with status 0 and its own address. Both from the address they wrote to."""
    game, player = udp(fam), udp(fam)
    register(game, version, "NAT " + label, dest)
    got = drain(game)
    assert len(got) == 1 and got[0][0][5] == 46, [g[0][:16] for g in got]
    seen = got[0][0]
    f, a, p, end = read_entry(seen, 14)
    gaddr, gport = own(game)
    if gaddr in ("0.0.0.0", "::"): gaddr = a
    assert (f, p) == (fam, gport) and end == len(seen) and len(seen) <= 33, (f, a, p, len(seen))
    assert got[0][1] == master_addr, "46 from %s, not %s" % (got[0][1], master_addr)
    ok("%s: a new game hears its public address from the master (46, %d bytes): %s port %d" % (label, len(seen), a, p))
    register(game, version, "NAT " + label, dest)
    assert drain(game, 0.3) == [], "46 more than once a minute"
    ok("%s: the next heartbeat gets no 46 (at most one a minute)" % label)

    nonce = 0x0123456789ABCDEF ^ fam
    fake = entry(fam, "203.0.113.66" if fam == 4 else "2001:db8:66::66", 4444)  # an address in the payload is ignored
    req = intro_request(nonce, version, fam, a, gport, padding=fake)
    assert len(req) == 128
    player.sendto(req, dest)
    to_game, to_player = drain(game), drain(player)
    assert len(to_game) == 1 and len(to_player) == 1, (to_game, to_player)
    intro, reply = to_game[0][0], to_player[0][0]
    assert struct.unpack_from("<IBBQ", intro) == (MAGIC, version, 41, nonce), intro[:14]
    f, ia, ip, end = read_entry(intro, 14)
    paddr, pport = own(player)
    assert (f, ip) == (fam, pport) and end == len(intro), (f, ia, ip)
    if paddr not in ("0.0.0.0", "::"): assert ia == paddr, (ia, paddr)
    assert to_game[0][1] == master_addr, "41 from %s, not %s (the host's firewall drops it)" % (to_game[0][1], master_addr)
    ok("%s: 41 to the game: player's nonce, the address the request came from (%s port %d), not the payload's; %d bytes"
       % (label, ia, ip, len(intro)))
    assert struct.unpack_from("<IBBQ", reply) == (MAGIC, version, 42, nonce) and reply[14] == 0, reply[:15]
    f, ra, rp, end = read_entry(reply, 15)
    assert (f, ra, rp) == (fam, ia, ip) and end == len(reply), (f, ra, rp)
    assert to_player[0][1] == master_addr, "42 from %s, not %s" % (to_player[0][1], master_addr)
    assert len(intro) + len(reply) <= 67 < len(req), (len(intro), len(reply))
    ok("%s: 42 to the player: status 0 + its own public address; 41 + 42 = %d bytes < 128 (no amplification)" %
       (label, len(intro) + len(reply)))

    for size in (127, 129, 14, 600):
        player.sendto(intro_request(nonce, version, fam, a, gport, size=size), dest)
    assert drain(player, 0.3) == [] and drain(game, 0.1) == [], "a request that isn't 128 bytes must be dropped"
    ok("%s: requests of 127, 129, 14 and 600 bytes are dropped (no reply, no introduction)" % label)

    player.sendto(intro_request(nonce, version + 1, fam, a, gport), dest)
    r = drain(player)
    assert len(r) == 1 and r[0][0][5] == 42 and r[0][0][14] == 1 and r[0][0][4] == version + 1, r
    assert drain(game, 0.1) == []
    ok("%s: another protocol version: status 1 (unknown game), no introduction" % label)

    player.sendto(intro_request(nonce, version, fam, a, gport + 1), dest)
    r = drain(player)
    assert len(r) == 1 and r[0][0][14] == 1 and drain(game, 0.1) == [], r
    ok("%s: an address:port that isn't a registered game: status 1, nobody is sent anything" % label)
    return game, player, a, gport


v4 = (host, port)
g4, p4, a4, port4 = check_flow(4, v4, host, 16, "IPv4")

if host6:
    v6 = (host6, port)
    g6, p6, a6, port6 = check_flow(6, v6, host6, 16, "IPv6")
    # a player on IPv6 can't use an introduction to an IPv4 game, nor the other way round
    p6.sendto(intro_request(7, 16, 4, a4, port4), v6)
    p4.sendto(intro_request(8, 16, 6, a6, port6), v4)
    r6, r4 = drain(p6), drain(p4)
    assert [x[0][14] for x in r6] == [1] and [x[0][14] for x in r4] == [1], (r6, r4)
    assert drain(g4, 0.1) == [] and drain(g6, 0.1) == []
    ok("an IPv6 player asking for an IPv4 game (and the reverse): status 1, no introduction")

# unlist: the game is gone, so is its introduction
g4.sendto(header(24, 0, 16), v4)
time.sleep(0.3)
p4.sendto(intro_request(9, 16, 4, a4, port4), v4)
r = drain(p4)
assert [x[0][14] for x in r] == [1] and drain(g4, 0.1) == [], r
ok("after unlist (24): status 1, no introduction")

if public_ip:
    # a game on the master's own network registers from a private address; the list shows it under --public-ip, and
    # an introduction asked for that address reaches it (by port among the private entries)
    lan = udp(4, "10.99.0.7")
    register(lan, 17, "LAN game", v4)
    drain(lan)
    player = udp(4, "198.51.100.77")
    player.sendto(intro_request(10, 17, 4, public_ip, lan.getsockname()[1]), v4)
    r, i = drain(player), drain(lan)
    assert [x[0][14] for x in r] == [0] and len(i) == 1 and i[0][0][5] == 41, (r, i)
    assert read_entry(i[0][0], 14)[1:3] == ("198.51.100.77", player.getsockname()[1])
    ok("a game on the master's network, asked for by the master's --public-ip %s: introduced" % public_ip)

if limits:
    dest6 = ("::1", port)
    game = udp(6, "2001:db8:70::1")
    register(game, 70, "limits", dest6)
    drain(game)
    ga, gp = own(game)

    def asks(sources, n_each=1, version=70):
        statuses = []
        for src in sources:
            s = udp(6, src)
            for k in range(n_each):
                s.sendto(intro_request(1000 + k, version, 6, ga, gp), dest6)
            statuses += [x[0][14] for x in drain(s, 0.15)]
        return statuses

    st = asks(["2001:db8:71:1::%x" % i for i in range(1, 15)])  # 14 addresses of one /64
    assert st == [0] * 10 + [2], st
    n = len(drain(game, 0.2))
    assert n == 10, n
    ok("per /64: 10 introductions per 10 s (14 addresses asking), one status 2, then silence; the game got 10")
    time.sleep(10.5)
    st = asks(["2001:db8:72:%x::1" % i for i in range(1, 46)])  # 45 /64s of one /48
    assert st == [0] * 30 + [2] * 10 + [2], (len(st), st)
    got = len(drain(game, 0.2))
    assert got == 30, got
    ok("per game: 30 introductions per 10 s, then status 2 (and per /48: 40, then one more status 2, then silence)")
    time.sleep(10.5)
    v4game = udp(4, "198.51.100.40")
    register(v4game, 71, "limits v4", ("127.0.0.1", port))
    drain(v4game)
    s = udp(4, "198.51.100.41")
    for k in range(13):
        s.sendto(intro_request(2000 + k, 71, 4, "198.51.100.40", v4game.getsockname()[1]), ("127.0.0.1", port))
    st = [x[0][14] for x in drain(s, 0.3)]
    assert st == [0] * 10 + [2], st
    ok("per IPv4 address: 10 introductions per 10 s, one status 2, then silence")

print("ok: %d NAT traversal checks" % checks)
