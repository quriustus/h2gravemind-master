#ifdef __APPLE__
#define __APPLE_USE_RFC_3542  // IPV6_RECVPKTINFO
#endif
#include "master_core.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
using SocketHandle = SOCKET;
using SockLen = int;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
using SockLen = socklen_t;
constexpr int INVALID_SOCKET = -1;
#endif

namespace
{
    constexpr uint32_t kMagic = 0x424C3248;  // "H2LB"
    constexpr uint8_t kHeartbeat = 8, kList = 9, kListReply = 10, kUnlist = 24;
    constexpr uint8_t kListReplyEx = 32;      // clear of the game's lobby message types (same header)
    constexpr uint8_t kListWantsFamily = 1;   // list request flag: type 32 replies (entries say IPv4 or IPv6)
    constexpr size_t kHeaderSize = 14;        // u32 magic, u8 version, u8 type, u64 nonce
    constexpr size_t kMaxPacket = 1472;       // one UDP packet without fragmentation
    constexpr size_t kMaxPacket6 = 1452;      // the same over IPv6 (40-byte IP header)
    constexpr size_t kMinInfo = 16, kMaxInfo = kMaxPacket - kHeaderSize - 1 - 6;
    constexpr size_t kEntriesPerPacket = 2;   // what the game reads per reply
    constexpr int64_t kExpireMs = 45000;
    // Per source: an IPv4 address or an IPv6 /64 (one subscriber's network); per IPv6 /48 (one site holds up to
    // 65536 /64s, so rotating them doesn't multiply the limits)
    constexpr size_t kMaxGames = 4096, kMaxGamesPerIp = 32, kMaxGamesPer48 = 256;
    constexpr int kListBurst = 6;             // list requests per source address and window (amplification guard)
    constexpr int kListBurst48 = 4 * kListBurst;
    constexpr int64_t kListWindowMs = 10000;

    int64_t NowMs()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    void CloseSocket(SocketHandle s)
    {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
    }

    // Which of the master's IPv6 addresses a request came to. A host has several (fixed, SLAAC, temporary) and
    // the system picks one for an unbound reply; the asker's firewall drops a reply from another address than it
    // sent to, so the reply leaves from this one. (IPv4 replies as before.)
    struct Arrival
    {
        bool known = false;
        in6_addr to{};
    };

#ifdef _WIN32
    LPFN_WSARECVMSG g_recvMsg = nullptr;
#endif

    void ReportArrival(SocketHandle s)
    {
        const int on = 1;
#ifdef _WIN32
        GUID id = WSAID_WSARECVMSG;
        DWORD bytes = 0;
        if (setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, reinterpret_cast<const char*>(&on), sizeof(on)) != 0 ||
            WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &g_recvMsg, sizeof(g_recvMsg), &bytes,
                     nullptr, nullptr) != 0)
            g_recvMsg = nullptr;
#else
        setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
#endif
    }

    int Receive(SocketHandle s, uint8_t* buf, size_t size, sockaddr_storage& from, SockLen& fromLen, Arrival& arrival)
    {
#ifdef _WIN32
        if (!g_recvMsg)
            return recvfrom(s, reinterpret_cast<char*>(buf), static_cast<int>(size), 0,
                            reinterpret_cast<sockaddr*>(&from), &fromLen);
        WSABUF data{static_cast<ULONG>(size), reinterpret_cast<char*>(buf)};
        char control[WSA_CMSG_SPACE(sizeof(IN6_PKTINFO))] = {};
        WSAMSG msg{};
        msg.name = reinterpret_cast<sockaddr*>(&from);
        msg.namelen = fromLen;
        msg.lpBuffers = &data;
        msg.dwBufferCount = 1;
        msg.Control = {sizeof(control), control};
        DWORD n = 0;
        if (g_recvMsg(s, &msg, &n, nullptr, nullptr) != 0) return -1;
        fromLen = msg.namelen;
        for (WSACMSGHDR* c = WSA_CMSG_FIRSTHDR(&msg); c; c = WSA_CMSG_NXTHDR(&msg, c))
            if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO)
                arrival.known = true, arrival.to = reinterpret_cast<IN6_PKTINFO*>(WSA_CMSG_DATA(c))->ipi6_addr;
        return static_cast<int>(n);
#else
        iovec data{buf, size};
        alignas(cmsghdr) char control[CMSG_SPACE(sizeof(in6_pktinfo))] = {};
        msghdr msg{};
        msg.msg_name = &from;
        msg.msg_namelen = fromLen;
        msg.msg_iov = &data;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        const int n = static_cast<int>(recvmsg(s, &msg, 0));
        fromLen = msg.msg_namelen;
        for (cmsghdr* c = CMSG_FIRSTHDR(&msg); n >= 0 && c; c = CMSG_NXTHDR(&msg, c))
            if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO)
            {
                in6_pktinfo info;
                std::memcpy(&info, CMSG_DATA(c), sizeof(info));
                arrival.known = true, arrival.to = info.ipi6_addr;
            }
        return n;
#endif
    }

    void Send(SocketHandle s, const std::vector<uint8_t>& packet, const sockaddr_storage& to, SockLen toLen,
              const Arrival& from)
    {
        if (!from.known)
        {
            sendto(s, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0,
                   reinterpret_cast<const sockaddr*>(&to), toLen);
            return;
        }
#ifdef _WIN32
        WSABUF data{static_cast<ULONG>(packet.size()), const_cast<char*>(reinterpret_cast<const char*>(packet.data()))};
        char control[WSA_CMSG_SPACE(sizeof(IN6_PKTINFO))] = {};
        WSAMSG msg{};
        msg.name = const_cast<sockaddr*>(reinterpret_cast<const sockaddr*>(&to));
        msg.namelen = toLen;
        msg.lpBuffers = &data;
        msg.dwBufferCount = 1;
        msg.Control = {sizeof(control), control};
        WSACMSGHDR* c = WSA_CMSG_FIRSTHDR(&msg);
        c->cmsg_level = IPPROTO_IPV6;
        c->cmsg_type = IPV6_PKTINFO;
        c->cmsg_len = WSA_CMSG_LEN(sizeof(IN6_PKTINFO));
        IN6_PKTINFO info{};
        info.ipi6_addr = from.to;
        std::memcpy(WSA_CMSG_DATA(c), &info, sizeof(info));
        DWORD sent = 0;
        WSASendMsg(s, &msg, 0, &sent, nullptr, nullptr);
#else
        iovec data{const_cast<uint8_t*>(packet.data()), packet.size()};
        alignas(cmsghdr) char control[CMSG_SPACE(sizeof(in6_pktinfo))] = {};
        msghdr msg{};
        msg.msg_name = const_cast<sockaddr_storage*>(&to);
        msg.msg_namelen = toLen;
        msg.msg_iov = &data;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        cmsghdr* c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = IPPROTO_IPV6;
        c->cmsg_type = IPV6_PKTINFO;
        c->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
        in6_pktinfo info{};
        info.ipi6_addr = from.to;
        std::memcpy(CMSG_DATA(c), &info, sizeof(info));
        sendmsg(s, &msg, 0);
#endif
    }

    // A game's or an asker's address. IPv4 also when it comes in on the IPv6 socket as ::ffff:a.b.c.d, so IPv4
    // games, limits and lists are the same as on an IPv4-only master. Sorted IPv4 first, in the order of before.
    struct Address
    {
        bool v6 = false;
        uint32_t ip4 = 0;                     // network byte order
        std::array<uint8_t, 16> ip6{};
        uint16_t port = 0;                    // network byte order
        auto Tie() const { return std::tie(v6, ip4, ip6, port); }
        bool operator<(const Address& o) const { return Tie() < o.Tie(); }
        bool operator==(const Address& o) const { return Tie() == o.Tie(); }
    };

    Address FromSockaddr(const sockaddr_storage& from)
    {
        static const uint8_t kMapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
        Address a;
        if (from.ss_family == AF_INET6)
        {
            const auto& in6 = reinterpret_cast<const sockaddr_in6&>(from);
            if (std::memcmp(in6.sin6_addr.s6_addr, kMapped, 12) == 0)
                std::memcpy(&a.ip4, in6.sin6_addr.s6_addr + 12, 4);
            else
            {
                a.v6 = true;
                std::memcpy(a.ip6.data(), in6.sin6_addr.s6_addr, 16);
            }
            a.port = in6.sin6_port;
        }
        else
        {
            const auto& in = reinterpret_cast<const sockaddr_in&>(from);
            a.ip4 = in.sin_addr.s_addr;
            a.port = in.sin_port;
        }
        return a;
    }

    // What a limit counts against: the IPv4 address, or the first 64 / 48 bits of an IPv6 address
    Address Prefix(Address a, int bits)
    {
        a.port = 0;
        if (a.v6)
            for (int i = bits / 8; i < 16; ++i) a.ip6[i] = 0;
        return a;
    }

    // 127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x (network byte order address)
    bool PrivateAddress(uint32_t netOrder)
    {
        const uint32_t a = ntohl(netOrder);
        return (a >> 24) == 127 || (a >> 24) == 10 || (a >> 20) == 0xAC1 || (a >> 16) == 0xC0A8 || (a >> 16) == 0xA9FE;
    }

    // IPv6: ::1, fe80::/10 (link-local), fc00::/7 (unique local)
    bool PrivateAddress(const Address& a)
    {
        if (!a.v6) return PrivateAddress(a.ip4);
        static const std::array<uint8_t, 16> kLoopback{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        return a.ip6 == kLoopback || (a.ip6[0] == 0xFE && (a.ip6[1] & 0xC0) == 0x80) || (a.ip6[0] & 0xFE) == 0xFC;
    }

    std::string IpPort(uint32_t netIp, uint16_t netPort)
    {
        char ip[INET_ADDRSTRLEN] = {};
        in_addr a{};
        a.s_addr = netIp;
        inet_ntop(AF_INET, &a, ip, sizeof(ip));
        return std::string(ip) + ":" + std::to_string(ntohs(netPort));
    }

    std::string IpPort(const Address& a)
    {
        if (!a.v6) return IpPort(a.ip4, a.port);
        char ip[INET6_ADDRSTRLEN] = {};
        in6_addr a6{};
        std::memcpy(a6.s6_addr, a.ip6.data(), 16);
        inet_ntop(AF_INET6, &a6, ip, sizeof(ip));
        return "[" + std::string(ip) + "]:" + std::to_string(ntohs(a.port));
    }

    // The game's info starts with its host name: 32 UTF-16LE characters.
    std::string HostName(const std::vector<uint8_t>& info)
    {
        std::string out;
        for (size_t i = 0; i + 1 < info.size() && i < 64; i += 2)
        {
            const unsigned c = info[i] | info[i + 1] << 8;
            if (!c) break;
            if (c < 0x80) out += static_cast<char>(c);
            else if (c < 0x800) out += {static_cast<char>(0xC0 | c >> 6), static_cast<char>(0x80 | (c & 0x3F))};
            else out += {static_cast<char>(0xE0 | c >> 12), static_cast<char>(0x80 | (c >> 6 & 0x3F)), static_cast<char>(0x80 | (c & 0x3F))};
        }
        return out;
    }

    struct Game
    {
        uint8_t version = 0;
        std::vector<uint8_t> info;
        int64_t lastSeen = 0;
    };

    // One window of list requests per key: window start, count. True while within the burst.
    bool Allow(std::map<Address, std::pair<int64_t, int>>& windows, const Address& key, int64_t now, int burst)
    {
        auto& [start, count] = windows[key];
        if (now - start > kListWindowMs) start = now, count = 0;
        return ++count <= burst;
    }
}

int RunMaster(const MasterOptions& options)
{
    auto log = [&](const std::string& line) {
        if (options.log) options.log(line);
        else std::printf("%s\n", line.c_str());
    };
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    // One socket for both: IPv6 with IPV6_V6ONLY off also takes IPv4 (Windows has it on by default). Without
    // IPv6 (disabled in the system, or options.ipv6 false) it is the IPv4 socket of before.
    SocketHandle s = INVALID_SOCKET;
    bool dualStack = false;
    if (options.ipv6 && (s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) != INVALID_SOCKET)
    {
        const int off = 0;
        sockaddr_in6 local6{};
        local6.sin6_family = AF_INET6;
        local6.sin6_port = htons(options.port);  // address :: (any)
        dualStack = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&off), sizeof(off)) == 0 &&
                    bind(s, reinterpret_cast<sockaddr*>(&local6), sizeof(local6)) == 0;
        if (dualStack)
            ReportArrival(s);
        else
        {
            CloseSocket(s);
            log("master: no IPv6 (IPv4 and IPv6 socket not available), IPv4 only");
        }
    }
    if (!dualStack)
    {
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = htons(options.port);
        if (s == INVALID_SOCKET || bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0)
        {
            log("master: cannot bind UDP port " + std::to_string(options.port));
            return 1;
        }
    }
    log("master: listening on UDP " + std::to_string(options.port) + (dualStack ? ", IPv4 and IPv6" : ", IPv4") +
        " (hosts register every 15 s, entries expire after 45 s)");

    std::atomic<uint32_t> publicIp{options.publicIp};
    if (options.fetchPublicIp)
        std::thread([&publicIp, fetch = options.fetchPublicIp, log] {
            for (;;)
            {
                if (uint32_t ip = fetch())
                {
                    if (ip != publicIp.exchange(ip)) log("master: public address " + IpPort(ip, 0));
                    std::this_thread::sleep_for(std::chrono::minutes(10));
                }
                else
                    std::this_thread::sleep_for(std::chrono::seconds(30));
            }
        }).detach();

    std::map<Address, Game> games;
    std::map<Address, std::pair<int64_t, int>> listRequests, listRequests48;  // source (/48) -> window start, count
    size_t lastCount = SIZE_MAX;
    int64_t lastSweep = NowMs();

    while (!(options.quit && options.quit()))
    {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(s, &readable);
        timeval timeout{0, 100000};
        if (select(static_cast<int>(s) + 1, &readable, nullptr, nullptr, &timeout) > 0)
        {
            uint8_t buf[2048];
            sockaddr_storage from{};
            SockLen fromLen = sizeof(from);
            Arrival arrival;
            const int n = Receive(s, buf, sizeof(buf), from, fromLen, arrival);
            uint32_t magic = 0;
            if (n >= static_cast<int>(kHeaderSize) && (std::memcpy(&magic, buf, 4), magic == kMagic))
            {
                const uint8_t version = buf[4], type = buf[5];
                const Address key = FromSockaddr(from);
                const int64_t now = NowMs();
                if (type == kHeartbeat && n >= static_cast<int>(kHeaderSize + kMinInfo) &&
                    n <= static_cast<int>(kHeaderSize + kMaxInfo))
                {
                    auto it = games.find(key);
                    if (it == games.end())
                    {
                        const Address net = Prefix(key, 64), site = Prefix(key, 48);
                        size_t fromIp = 0, fromSite = 0;
                        for (auto& [k, g] : games)
                        {
                            fromIp += Prefix(k, 64) == net;
                            fromSite += key.v6 && Prefix(k, 48) == site;
                        }
                        if (games.size() >= kMaxGames || fromIp >= kMaxGamesPerIp || fromSite >= kMaxGamesPer48)
                            continue;
                        it = games.emplace(key, Game{}).first;
                        it->second.info.assign(buf + kHeaderSize, buf + n);
                        log("master: " + HostName(it->second.info) + " registered from " + IpPort(key) +
                            " (protocol " + std::to_string(version) + ")");
                    }
                    it->second.version = version;
                    it->second.info.assign(buf + kHeaderSize, buf + n);
                    it->second.lastSeen = now;
                }
                else if (type == kUnlist)
                {
                    // the host closed its game: gone from the lists at once (not 45 s later), IPv4 and IPv6 alike.
                    // Only the entry of the address and port the unlist comes from, as for heartbeats.
                    if (auto it = games.find(key); it != games.end())
                    {
                        log("master: " + HostName(it->second.info) + " closed (" + IpPort(key) + ")");
                        games.erase(it);
                    }
                }
                else if (type == kList)
                {
                    if (!Allow(listRequests, Prefix(key, 64), now, kListBurst)) continue;
                    if (key.v6 && !Allow(listRequests48, Prefix(key, 48), now, kListBurst48)) continue;
                    // Flags byte after the header (new browsers): bit 0 = entries with their address family
                    const bool withFamily = n > static_cast<int>(kHeaderSize) && (buf[kHeaderSize] & kListWantsFamily);
                    const bool outside = !PrivateAddress(key);
                    const size_t maxPacket = key.v6 ? kMaxPacket6 : kMaxPacket;
                    std::vector<uint8_t> reply;
                    uint8_t inPacket = 0;
                    auto flush = [&] {
                        reply[kHeaderSize] = inPacket;
                        Send(s, reply, from, fromLen, key.v6 ? arrival : Arrival{});
                    };
                    auto begin = [&] {
                        reply.assign(buf, buf + kHeaderSize);  // magic, the asker's version, its nonce
                        reply[5] = withFamily ? kListReplyEx : kListReply;
                        reply.push_back(0);
                        inPacket = 0;
                    };
                    auto append = [&reply](const void* data, size_t size) {
                        const uint8_t* p = static_cast<const uint8_t*>(data);
                        reply.insert(reply.end(), p, p + size);
                    };
                    begin();
                    for (auto& [k, g] : games)
                    {
                        if (g.version != version || (k.v6 && !withFamily)) continue;  // type 10 is IPv4 only
                        Address a = k;
                        if (outside && PrivateAddress(a))
                        {
                            if (a.v6) continue;  // no NAT on IPv6: a ULA / link-local address is no use outside
                            if (publicIp) a.ip4 = publicIp;  // a game on the master's network
                        }
                        const size_t size = withFamily ? 1 + (a.v6 ? 16 : 4) + 2 + 2 + g.info.size() : 6 + g.info.size();
                        if (inPacket == kEntriesPerPacket || reply.size() + size > maxPacket)
                        {
                            flush();
                            begin();
                        }
                        if (withFamily)
                        {
                            reply.push_back(a.v6 ? 6 : 4);
                            if (a.v6) append(a.ip6.data(), 16);
                            else append(&a.ip4, 4);
                            append(&a.port, 2);
                            reply.push_back(static_cast<uint8_t>(g.info.size()));
                            reply.push_back(static_cast<uint8_t>(g.info.size() >> 8));
                        }
                        else
                        {
                            append(&a.ip4, 4);
                            append(&a.port, 2);
                        }
                        reply.insert(reply.end(), g.info.begin(), g.info.end());
                        ++inPacket;
                    }
                    flush();  // also an empty list: the browser knows the master answered
                }
            }
        }

        const int64_t now = NowMs();
        if (now - lastSweep > 1000)
        {
            lastSweep = now;
            for (auto it = games.begin(); it != games.end();)
                it = now - it->second.lastSeen > kExpireMs ? games.erase(it) : std::next(it);
            for (auto* windows : {&listRequests, &listRequests48})
                for (auto it = windows->begin(); it != windows->end();)
                    it = now - it->second.first > kListWindowMs ? windows->erase(it) : std::next(it);
            if (games.size() != lastCount)
            {
                lastCount = games.size();
                log("master: " + std::to_string(lastCount) + " game(s) registered");
                if (options.printList)
                    for (auto& [k, g] : games)
                        log("  " + IpPort(k) + "  " + HostName(g.info) + "  (protocol " + std::to_string(g.version) +
                            ")");
            }
        }
    }
    CloseSocket(s);
    return 0;
}
