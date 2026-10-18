# Halo 2 Project Gravemind master server (UDP 11770). Build from the repository root:
#   docker build -f master/Dockerfile -t h2gravemind-master .
#   docker run -d --name h2gravemind-master --restart unless-stopped --network host h2gravemind-master
# (--network host so IPv6 games keep their address; see master/README.md)
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY src/master_core.h src/master_core.cpp src/
COPY master/main.cpp master/
RUN g++ -O2 -std=c++17 -Wall -Wextra -o /h2gravemind-master master/main.cpp src/master_core.cpp -pthread

FROM debian:bookworm-slim
COPY --from=build /h2gravemind-master /usr/local/bin/h2gravemind-master
USER nobody
EXPOSE 11770/udp
ENTRYPOINT ["/usr/local/bin/h2gravemind-master"]
