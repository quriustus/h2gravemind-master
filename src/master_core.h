#pragma once
// The master server's core, portable (Windows: h2gravemind.exe --master; Linux / Docker: master/, no game code).
// It does not depend on the game's protocol version: a heartbeat (header type 8) is kept as it came (the version
// and the game's info bytes), entries expire after 45 s, and a list request (type 9) gets the entries of its own
// protocol version (type 10 replies: u8 count, then {u32 ipv4, u16 port, info} entries, at most 2 per packet). So
// masters run by others keep working when the game's protocol changes.
// Header (packed, little endian): u32 magic "H2LB", u8 version, u8 type, u64 nonce (echoed in the reply).
// IPv4 and IPv6 on one socket (IPv4 arrives as ::ffff:a.b.c.d and is handled exactly as on an IPv4-only master).
// A list request carrying a flags byte after the header with bit 0 set gets type 32 replies instead: u8 count, then
// {u8 family (4 or 6), IPv4 (4 bytes) or IPv6 (16 bytes), u16 port, u16 info size, info} entries, IPv4 and IPv6
// games mixed (32: clear of the game's own message types, which share this header). Plain type 9 requests (the
// current game) get the type 10 list of before, IPv4 games only; masters without this change ignore the flags byte
// and answer type 10, so a new browser works with any master.
// NAT traversal: a player asks from its game socket to be introduced to a listed game (40, exactly 128 bytes: u8
// flags, the game's entry, zero padding); the game's host gets the player's address as we saw it (41: an entry; the
// header nonce is the player's) and the player a reply (42: u8 status 0 introduced / 1 unknown game / 2 rate
// limited, then its own entry). Hosts hear their own public address once a minute (46: an entry, after a
// heartbeat). Games and masters without this ignore the four types. Entries as in type 32 (family, address, port).
#include <cstdint>
#include <functional>
#include <string>

constexpr uint16_t kMasterDefaultPort = 11770;

struct MasterOptions
{
    uint16_t port = kMasterDefaultPort;
    // The master's public IPv4 (network byte order), for games on the master's own network: players on the
    // internet get it instead of the game's private address. 0 = none; fetchPublicIp (if set) refreshes it.
    uint32_t publicIp = 0;
    std::function<uint32_t()> fetchPublicIp;
    std::function<bool()> quit;               // polled; true stops the master
    std::function<void(const std::string&)> log;  // one line, no newline
    bool printList = true;                    // print the registered games when the list changes
    bool ipv6 = true;                         // false: IPv4 socket only (as before); also the fallback without IPv6
};

int RunMaster(const MasterOptions& options);
