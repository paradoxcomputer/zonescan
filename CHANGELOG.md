# Changelog

Notable changes to **zonescan**. Versioning is semver-ish for a 0.x project: a minor bump
(`0.x`) carries new features, a patch bump (`0.x.y`) carries fixes.

## [0.5.0] — 2026-07-31

### Added
- The dashboard footer now names the build serving the page: `zonescan v<version> · <git rev>`
  (a `-dirty` suffix when the binary contains uncommitted work). A new `build.rs` captures the
  revision at compile time and degrades to the bare version when git isn't available (release
  tarball, vendored crate, npm package), so nothing depends on it being present.
- **LEZ v0.2.0 (final)** — the decoder now links the official `v0.2.0` release (was
  `v0.2.0-rc5`). The on-chain wire format is identical (verified byte-for-byte: block
  layout, header-hash preimage, transaction encodings, instruction shapes), so decoding
  and chain verification of rc4/rc5 zones is unchanged; the port is API-level only
  (built-in program constructors moved to the new `programs` crate). Zones running the
  stock v0.2.0 build are now named natively and badge **v0.2**, and the three new
  built-ins — **vault, faucet, bridge** — resolve by name offline.
- **Data-channel discovery** — auto-discovery now also adopts channels whose inscriptions
  are **not** valid LEZ sequencer blocks (raw text/JSON/data payloads, e.g. cid-pin
  registries). They are tracked and indexed like any channel — each inscription renders as
  a raw row with its content — and carry an explicit amber **`data`** badge on the zones
  list and zone page (whose header says *Channel*, not *Sequencer*) so they are never
  mistaken for a sequencer. Sequencers are admitted to the discovery cap first; opt out
  with `ZONE_SCAN_DISCOVER_DATA=0` (config: `discover_data: false`).
- The setup page now preserves the `discovered`/`data_channel` flags of already-tracked
  channels across a form save (previously a save silently reset them to hand-configured).
- **Zones filter** — an **All | rc | data** segmented control on the zones list.
- **Observed data-channel classification** — a channel whose observed content is only raw
  inscriptions (never a valid LEZ block) now badges `data` even when hand-configured, so
  e.g. a guest text channel no longer shows under the `rc` filter as a "sequencer".
- **Token names resolve without an ATA link** — a transfer on a (fingerprinted) token
  program whose accounts have no learned ATA/holding link now falls back to the program's
  own definitions, when they carry exactly one distinct token name (a new `prog_def`
  index, populated on ingest and by the token-map re-learn). Fixes transfers showing an
  amount but no token symbol when the ATA-create predates the scan window.
- **cid_pin viewer** — a raw inscription recognized as a keeper `cid_pin` record renders a
  structured "Pinned content" panel on its transaction page: title, source (linked to
  archive.org for Internet Archive items), pinner, pin time, total size, and a per-file
  table with **view/download links through an IPFS gateway** (`ZONE_SCAN_IPFS_GATEWAY`,
  default `https://ipfs.io`). The tx-page headline reads `Pinned · <title>`; tx tables keep
  the plain Inscription type badge. The exact on-chain payload stays visible below the
  structured panel.

### Changed
- The Paradox zone moved to a fresh channel for the LEZ v0.2.0 upgrade (v0.2.0 program
  ImageIDs are incompatible with the rc5 chain state): `7777…77` is now aliased
  "Paradox Computer", and the retired rc5 channel `8888…88` (frozen at block 42036 on
  2026-07-31) is kept tracked as "Paradox Computer (old)". CLI aliases `paradox` /
  `paradox-old` added.
- Discovery no longer calls what it finds "rc4-compatible sequencer(s)" in its log line and
  docs. The check has been build-agnostic for a long time (anything whose inscriptions
  decode as LEZ sequencer blocks, rc3 through v0.2.0), so the wording was misleading.
- The program-fingerprint classifier now runs one pass **immediately** at startup instead of
  waiting a fixed 8s. On a restart the store is already full of txs, so that sleep created a
  window where foreign-program token names resolved to `None` for no reason. A cold store
  makes the early pass a no-op, so nothing is spent when there's nothing to classify.

### Fixed
- **Transactions shared between zones no longer overwrite each other.** Tx rows were keyed by
  hash alone, but a hash covers program + accounts + instruction data and *not* the channel —
  so two zones bootstrapped from the same genesis config produce byte-identical genesis txs
  with identical hashes, and the second zone's copy deduped into the first zone's record. The
  effect was silent: a whole zone's genesis disappeared, its transactions rendered under the
  other zone, and per-zone counts were wrong. (Observed live: all three of the new Paradox
  zone's genesis txs were stored under the `0101…` dev channel, so its zone page showed one
  transaction instead of its genesis set.) Identity is now `(hash, channel)` in the tx table
  and in every derived index and pagination cursor; `/api/tx/<hash>` takes an optional
  `?channel=` and the dashboard passes the zone from the URL, falling back to whichever zone
  carries the hash so unscoped links still resolve. Existing stores are re-keyed in place on
  first open — no data loss, and the indexes are rebuilt from the tx rows so a half-migrated
  mix is impossible. Rows that were already lost to the old key return on the next scan of
  their L1 slots (`/api/rescan`).
- The "finalizing" tooltip claimed finality takes "~1h" — a hardcoded constant that was
  never computed from anything. Time-to-finality is now **measured**: zonescan samples the
  L1 tip slot alongside the existing finality-lag samples, derives seconds-per-slot from
  the observed rate, and reports `lag × rate`. When the rate hasn't been observed for long
  enough to trust (< 2 min of samples, a stalled tip, or a rewound one) it states the lag
  in slots rather than inventing a duration. Measured live on 2026-07-31: 1.28 s/slot and
  3425 slots of lag = ~73 min, so the old constant was both fabricated *and* wrong — and
  wrong by an amount that drifts, which is exactly why a constant could never work.
- Channel balances lost precision above 2^53: they were rendered with `num()`
  (`Number(n).toLocaleString()`) even though the server sends `l1_balance` as a u128 string.
  `u128::MAX` displayed as `340,282,366,920,938,500,000,…`. All three surfaces (zone list,
  zone panel, zone page) now use the bigint-safe `grp()` already used for transfer amounts.
- Zone version badges now re-tag when a zone **upgrades its build** — the version was set
  once and persisted, so a zone that moved from a fork build to stock v0.2.0 (e.g. the
  `0101` dev channel) kept showing the stale `rc5` badge forever. It now tracks the latest
  build-distinctive program signal; shared/neutral programs (clock) never clobber a tag.
- The transaction page no longer visibly reloads on every live snapshot (it re-fetched and
  rebuilt the whole page every few seconds, losing scroll position). The finality badge —
  the only live-updating element there — now refreshes in place.
- Foreign-token-program transfers showed "(token unresolved)" on the tx page even when the
  server had resolved the token: the raw-id render branches only consulted the fingerprint
  guess (`token_guess`), never the resolved `token` field. Resolved beats guess now.
- The Instruction row now decodes semantically for **fingerprinted** programs: a program
  the classifier confidently recognizes (e.g. `≈ token`) renders through the same typed
  branch as the named built-in — `≈ token · Transfer 10,000,000,000 RLNTOK` instead of a
  generic inferred-field dump — and the async layout-inference no longer overwrites a
  semantic decode. The server-resolved token symbol labels the transfer when no linked
  definition is available.
- The tx-page headline mis-decoded rc5 native (authenticated_transfer) amounts: it read the
  u128 at word 0, folding the enum variant into the low limb, so a 1-LEZ transfer showed as
  4,294,967,296 LEZ. It now uses the server-decoded amount (both rc4 bare and rc5 enum
  shapes), and the 1-word rc5 CreateAccount renders as "Register native account" instead of
  an empty transfer.

## [0.4.0] — 2026-07-06

### Added
- **Per-program index** — program-page lookups are now O(limit) with an **exact** per-program
  transaction total, replacing an up-to-50k channel scan; the program page shows that exact count.
- **Live updates on every page** — the SSE feed appends new transactions on account, token, and
  program pages (not just the main feed), and the transaction page's finality badge advances live.
- **Zone throughput + tx mix** — blocks/min and the public / private / deploy transaction mix on
  the zones list and the zone page.
- **Finality-lag sparkline** — a bounded time series of L1 finality lag on the dashboard.
- **Token holders** list with infinite scroll on the token page, and a **token-holdings** panel on
  account pages (owner → ATA index; balances via the sequencer RPC).
- **Search a token definition** routes straight to its token page.
- Comma-grouped amounts throughout the UI.
- ABI submitters can set a **program-name alias**.
- Richer classification of foreign / rebuilt programs: multi-variant token fingerprint profiles,
  on-chain token-name extraction, a generic `≈ transfer` fallback, and per-transaction amount decode.

### Fixed
- rc5 `authenticated_transfer` decoded as an enum (`Transfer`@0 / `CreateAccount`@1).
- Amounts decoded by instruction **shape** (guess-independent) for foreign `authenticated_transfer`
  / `pinata` / verified non-token programs; faucet-vault genesis amounts and large (>u64) supplies.
- Token page now includes ATA↔ATA transfers (previously invisible); token-holding balances read
  from the sequencer RPC (were showing the native balance, 0).
- Dropped a stale hardcoded token-ticker table that mis-classified dead definition ids; names are
  learned from the chain.
- Finality re-promotion after ingest; shield/deshield relabel after sequencer-RPC ingest; the Type
  filter resolves program id → name; removed a dead write-amplifying index.

### Changed
- **Decode dependency ported to the official LEZ `v0.2.0-rc5`** — the version the live sequencers
  run. rc5 restructured the workspace, so the decoder now depends on `common` + `lee` (the `nssa`
  crate was folded into `lee`). Decoding of the live rc5 chain is verified: block hashes recompute
  with zero mismatches.
- README decoding section updated (fingerprint classifier, program naming across rebuilds, ABI/alias
  registration).

## [0.3.0] — 2026-06-26

- First public release: dual Logos L1 `0.1.x` / `0.2.x` support, per-transaction decoding, the
  structural fingerprint classifier, and the multi-zone dashboard.

[0.5.0]: https://github.com/paradoxcomputer/zonescan/releases/tag/v0.5.0
[0.4.0]: https://github.com/paradoxcomputer/zonescan/releases/tag/v0.4.0
[0.3.0]: https://github.com/paradoxcomputer/zonescan/releases/tag/v0.3.0
