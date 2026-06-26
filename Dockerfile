# zone-scan container image.
#
# The full explorer needs the `decode` feature, which depends on the LEZ
# workspace (common/nssa) via path deps that live OUTSIDE this repo - so it
# cannot be `cargo build`-ed from this directory alone (see README "Building").
# This image therefore packages a PRE-BUILT binary: build it on a host that has
# the LEZ workspace checked out alongside, then `docker build`.
#
#   cargo build --release --features decode      # produces target/release/zone-scan
#   docker build -t zone-scan .
#   docker run --rm -p 8088:8088 -v zone-scan-data:/data zone-scan
#
# The base is ubuntu:24.04 to match a modern host glibc; if you build the binary
# on an older distro, switch the base to match (or build a musl static binary).
# A Tor daemon is bundled so .onion L1 nodes work out of the box (SOCKS
# 127.0.0.1:9050 inside the container); set ZONE_SCAN_TOR=0 to disable it and
# point --socks5 at an external proxy instead.
FROM ubuntu:24.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tor \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 -s /usr/sbin/nologin app \
 && mkdir -p /data && chown app:app /data

COPY target/release/zone-scan /usr/local/bin/zone-scan
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/zone-scan /usr/local/bin/docker-entrypoint.sh

USER app
WORKDIR /data
# config.json + the redb store live here - mount a volume to persist them
VOLUME ["/data"]
EXPOSE 8088
ENV ZONE_SCAN_PORT=8088 ZONE_SCAN_TOR=1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
