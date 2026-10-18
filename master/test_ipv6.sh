#!/bin/sh
# IPv6 tests in a throwaway container (Docker, nothing installed on the machine): builds the master before this
# change (git commit, default dd4943d) and after it with g++, then runs smoke_test.py (IPv4, IPv6, unlist, caps and
# rate limits) and compat_test.py (the current game's list byte for byte, before and after unlist). From the
# repository root:
#   sh master/test_ipv6.sh [base commit]
set -e
base=${1:-dd4943d}
old=$(mktemp -d)
git archive "$base" src master/main.cpp | tar -x -C "$old"
docker run --rm --cap-add NET_ADMIN \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
    --sysctl net.ipv6.ip_nonlocal_bind=1 --sysctl net.ipv4.ip_nonlocal_bind=1 \
    -v "$PWD:/src:ro" -v "$old:/old:ro" debian:bookworm-slim sh -ec '
        apt-get update -qq && apt-get install -y -qq --no-install-recommends g++ python3 iproute2 >/dev/null
        ip -6 route add local 2001:db8::/32 dev lo
        ip -6 route add local fd00:db8::/32 dev lo
        ip route add local 198.51.100.0/24 dev lo
        ip route add local 10.99.0.0/16 dev lo
        g++ -O2 -std=c++17 -Wall -Wextra -o /tmp/old /old/master/main.cpp /old/src/master_core.cpp -pthread
        g++ -O2 -std=c++17 -Wall -Wextra -Werror -o /tmp/new /src/master/main.cpp /src/src/master_core.cpp -pthread
        /tmp/new --port 11791 > /tmp/new.log & master=$!
        sleep 0.5
        python3 /src/master/smoke_test.py 127.0.0.1 11791 --v6 ::1 --limits
        python3 /src/master/compat_test.py /tmp/old /tmp/new
        kill $master
        # replies from the address asked: the browser on another of the machine'"'"'s addresses
        ip -6 addr add 2001:db8:ffff::10/128 dev lo
        ip -6 addr add 2001:db8:ffff::20/128 dev lo
        /tmp/new --port 11771 > /tmp/new2.log & master=$!
        sleep 0.5
        python3 /src/master/smoke_test.py 127.0.0.1 11771 --v6 2001:db8:ffff::20 --v6-from 2001:db8:ffff::10
        kill $master'
rm -rf "$old"
