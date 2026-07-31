# zonescan

A live transaction explorer for **Logos Execution Zone (LEZ)** sequencers. It serves a
web dashboard over public on-chain settlement data: a per-sequencer transaction feed,
transaction detail, account / program / token pages, and liveness (tip, cadence, consistency).

## Install

```sh
npm install -g @paradoxcomputer/zonescan
```

Downloads a prebuilt binary for your platform (or builds from source with Rust if none fits).

### Transaction decoding (optional)

By default zonescan includes **full per-transaction decoding**: it turns each program's
risc0-serialized instruction into typed fields — tx type, program, token transfer amounts and
learned token names, mints/burns, faucet claims, ATA creates, and shield vs. deshield. Programs
are named by a **structural fingerprint classifier** that recognizes the built-ins even when a
sequencer rebuild gives them different image ids, and operators can register an **ABI/schema**
(and a program-name alias) for any program it doesn't yet know. Every release also ships a
**light** prebuilt that omits decoding, useful because the full build is heavy (it pulls the
logos-blockchain + risc0 stack). To install the light binary instead:

```sh
ZONE_SCAN_DECODE=0 npm install -g @paradoxcomputer/zonescan
```

The light binary is fast and reliable and still shows block-level data + liveness/consistency,
just not the per-transaction type/program breakdown. Both come as **prebuilt binaries**, so
neither needs a Rust toolchain; the light one is also served automatically to any platform
that has no full build. (If you *do* build the full binary from source and that heavy build
fails, the launcher falls back to a light build automatically.)

## Commands

```sh
zonescan setup     # configure via a token-gated setup page, then run
zonescan up        # start in the background
zonescan down      # stop the background server
zonescan           # run in the foreground (Ctrl-C to stop)
```

`setup` starts the dashboard (default `http://127.0.0.1:8088`), prints a one-time setup
URL with a token, and opens it. On that page you pick a data source (see **Modes**) and
the sequencer(s) to watch, and it starts scanning. After that, `zonescan up` / `zonescan`
just run it. The dashboard and read APIs are open; **changing configuration requires the
setup token**.

## Modes

zonescan reads the **same** settlement data from one of two vantage points. Pick one on
the setup page, or set it via env / `.env` (copy `.env.example`).

### With an L1 node (the trustless vantage)

Point it at a **Logos L1 node**. Every sequencer settles its blocks to the L1, so a single
node sees them all and a sequencer can neither lie about nor hide what it settled. This mode
adds L1 finality / lag, on-chain channel collateral, and can auto-discover sequencers.
Discovery also adopts **data channels** — channels whose inscriptions are raw text/data
payloads rather than valid LEZ sequencer blocks (e.g. cid-pin registries). They are
indexed like any channel, each inscription shown as a raw row, and badged `data` in the
UI so they are never mistaken for a sequencer. Set `ZONE_SCAN_DISCOVER_DATA=0` to
auto-track real sequencers only. Recognized formats get a structured view: a `cid_pin`
record renders its title, source and per-file IPFS view/download links on the
transaction page (gateway configurable via `ZONE_SCAN_IPFS_GATEWAY`, default ipfs.io).

```sh
ZONE_SCAN_L1_NODE_URL=http://localhost:8080
ZONE_SCAN_SEQUENCERS=<channel-id>          # or leave empty to track every channel on the L1
# For a Tor .onion L1 node, route through a SOCKS5 proxy:
# ZONE_SCAN_SOCKS5=127.0.0.1:9050
```

### Without an L1 (straight from a local sequencer)

Leave the L1 URL empty and give a **sequencer's JSON-RPC** URL. zonescan reads blocks
directly from the sequencer (`getLastBlockId` / `getBlock`). It works fully offline against
a local sequencer with no L1 connection. (L1-only extras like finality and collateral aren't
shown in this mode; everything else is.)

```sh
ZONE_SCAN_SEQUENCERS=<channel-id>|http://127.0.0.1:3040
```

## Logos L1 compatibility

zonescan speaks the **Logos Testnet v0.2 (0.2.0)** L1 REST API and stays **back-compatible
with 0.1.x** — it auto-detects the response shape per node, so the same binary works against
either. Point `ZONE_SCAN_L1_NODE_URL` at the node's API (`:8080`). The dashboard header shows
an **L1-version tag** (`L1 v0.2.x` / `L1 v0.1.x`) next to the sync status, so you can see which
API a node is serving at a glance.

### Channel aliases

Known sequencer channels render a friendly name as the primary label (with the raw short
hex kept alongside) everywhere a channel id is shown — the channels list, a sequencer's
header, and per-channel labels. Channels without an alias keep the plain short-hex display.

## Configuration

All settings are `ZONE_SCAN_*` environment variables (also loadable from `.env`). The common ones:

| Variable | Meaning | Default |
| --- | --- | --- |
| `ZONE_SCAN_L1_NODE_URL` | L1 node URL. Empty ⇒ no-L1 (local sequencer) mode. | unset |
| `ZONE_SCAN_SEQUENCERS` | Comma-separated `channel\|rpc_url\|label\|full` entries (only `channel` required). | unset |
| `ZONE_SCAN_SOCKS5` | SOCKS5 proxy for a Tor `.onion` L1 node. | unset |
| `ZONE_SCAN_HOST` / `ZONE_SCAN_PORT` | Bind address / port. | `127.0.0.1` / `8088` |
| `ZONE_SCAN_DATA` | Data directory (config, store, setup token). | `~/.config/zone-scan` |
| `ZONE_SCAN_ADMIN_TOKEN` | Stable setup token (otherwise one is generated). | generated |

Full list with comments in [`.env.example`](.env.example).

## Build from source

```sh
npm run build          # cargo build --release --features decode
```

## License

GPLv3. See [LICENSE](LICENSE).
