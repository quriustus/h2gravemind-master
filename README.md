# Halo 2 Project Gravemind — master server

The master server keeps the internet list of games. It is tiny and stateless:

- **UDP 11770** only (no TCP, no HTTP), **IPv4 and IPv6** on one socket (IPv4 only where the system has no IPv6).
- Games (player-hosted lobbies and dedicated servers) send a heartbeat every 15 s; an entry expires after 45 s,
  or at once when the game says it closed (unlist).
- Players' server browsers ask for the list; the master answers with the games of the **same protocol version**
  (it stores each game's info as opaque bytes, so it keeps working when the game's protocol changes — masters
  never need updating for a new game version).
- No database, no disk, no configuration. Memory use is a few MB.
- Limits: 4096 games in total, 32 per source address, 6 list requests per address every 10 s (the list reply is
  larger than the request, so this keeps it from being used to reflect traffic). An IPv6 source is its /64 (one
  subscriber's network: rotating addresses inside it doesn't help), and a /48 (one site) gets at most 256 games
  and 24 list requests every 10 s.
- IPv6: games that heartbeat over IPv6 are listed with their IPv6 address to browsers that ask for the new list
  (type 32, see Protocol). The current game's list (type 10) is the same as before, byte for byte: IPv4 games only.

The game ships with `master01.gravemind.haloarchive.com:11770` and `master02.gravemind.haloarchive.com:11770` as
its default masters. Every game registers with **all** the masters in the player's list and the browser asks all
of them and merges the lists, so masters back each other up; any number can be added.

## Docker

Build from the repository root:

```sh
docker build -f master/Dockerfile -t h2gravemind-master .
docker run -d --name h2gravemind-master --restart unless-stopped --network host h2gravemind-master
```

`--network host` for IPv6: with `-p 11770:11770/udp` on a Docker network without IPv6, Docker's proxy takes the
IPv6 packets and passes them on over IPv4, so every IPv6 game would look like the Docker gateway (172.17.0.1).
(`-p 11770:11770/udp` is still fine for IPv4 only, or on a Docker network created with `--ipv6`.)

docker compose:

```yaml
services:
  master:
    build:
      context: .
      dockerfile: master/Dockerfile
    restart: unless-stopped
    network_mode: host
```

Logs go to stdout (`docker logs h2gravemind-master`): one line per game that registers and the count when it
changes.

Options: `--port N` (or the `MASTER_PORT` environment variable), `--public-ip a.b.c.d` (only needed when games
run on the master's own private network: players on the internet then get that address for them) and
`--ipv4-only`. There is no IPv6 equivalent of `--public-ip` (no NAT): a game on a ULA or link-local IPv6 address
(fc00::/7, fe80::/10) is listed only to browsers on such addresses.

Replies over IPv6 leave from the address the request came to (a host has several IPv6 addresses, and a reply
from another one is dropped by the asker's firewall). Wine 10 ignores that (the system picks the address), so
`h2gravemind.exe --master` under Wine should run on a host whose published IPv6 address is the one it picks.

Without Docker: `g++ -O2 -std=c++17 -o h2gravemind-master master/main.cpp src/master_core.cpp -pthread`.

## Checking it

`python3 master/smoke_test.py <host> 11770` registers a fake game and asks for the list. With
`--v6 <IPv6 address>` it also checks IPv6 games, the mixed list and that the current game's list is unchanged.

`sh master/test_ipv6.sh` (Docker) builds the master before and after the IPv6 change in a throwaway container and
runs the smoke test with the IPv6 caps and rate limits, plus `master/compat_test.py`: every list reply the current
game can get, compared byte for byte between the two.

## Protocol

Little endian, packed. Header (14 bytes): `u32 magic 0x424C3248 ("H2LB")`, `u8 protocol version`, `u8 type`,
`u64 nonce`.

- type 8, heartbeat (game -> master): header + the game's info (16..1451 bytes, opaque to the master; it starts
  with the host name, 32 UTF-16LE characters).
- type 9, list request (browser -> master): header, optionally followed by `u8 flags`. Flag bit 0: answer with
  type 32 (IPv4 and IPv6 games). Other bits are ignored (for later). Masters before the IPv6 change ignore the
  flags byte and answer type 10, so a browser that sends it works with every master: it reads type 10 and 32.
- type 10, list reply (master -> browser): the request's header with type 10 (same version and nonce), `u8
  count`, then `count` entries `{u32 IPv4, u16 port (both network byte order), info}`, at most 2 per packet,
  as many packets as needed (one with count 0 when the list is empty). IPv4 games only.
- type 32, list reply with address families (master -> browser, to a type 9 with flag bit 0): the request's
  header with type 32, `u8 count`, then `count` entries `{u8 family (4 or 6), IPv4 (4 bytes) or IPv6 (16 bytes),
  u16 port (address and port in network byte order), u16 info size, info}`, IPv4 and IPv6 games together, at most
  2 per packet (packets up to 1472 bytes, 1452 to an IPv6 browser). A game on both IPv4 and IPv6 that heartbeats
  over both is two entries with the same info: the browser shows it once and tries IPv6 first. (32 rather than
  11: the game's lobby messages use this header too, with types from 1 up.)
- type 24, unlist (game -> master): header only. The game closed: the master drops it from the list at once
  (instead of 45 s after its last heartbeat), from the type 10 and the type 32 lists alike. Only the entry of
  the address and port it comes from (IPv4 or IPv6), as for heartbeats. Masters without it simply ignore the
  message.
