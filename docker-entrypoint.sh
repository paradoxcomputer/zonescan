#!/bin/sh
# Container entrypoint: optionally start a bundled Tor (so .onion L1 nodes work
# with no host setup), then run the explorer bound to all interfaces. Everything
# is driven by ZONE_SCAN_* env vars (see .env.example); the data dir defaults to
# the /data volume so config.json, the store and the setup-token persist.
set -e

export ZONE_SCAN_DATA="${ZONE_SCAN_DATA:-/data}"
export ZONE_SCAN_HOST="${ZONE_SCAN_HOST:-0.0.0.0}"
export ZONE_SCAN_PORT="${ZONE_SCAN_PORT:-8088}"
mkdir -p "$ZONE_SCAN_DATA"

if [ "${ZONE_SCAN_TOR:-1}" = "1" ]; then
  echo "zone-scan: starting bundled Tor (SOCKS 127.0.0.1:9050) for .onion L1 access…"
  tor --SocksPort 127.0.0.1:9050 \
      --DataDirectory "$ZONE_SCAN_DATA/tor" \
      --Log "warn stderr" \
      --RunAsDaemon 0 &
  # Set ZONE_SCAN_SOCKS5=127.0.0.1:9050 (env or on the setup page) to reach an .onion L1.
fi

exec zone-scan
