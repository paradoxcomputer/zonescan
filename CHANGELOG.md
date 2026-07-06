# Changelog

Notable changes to **zonescan**. Versioning is semver-ish for a 0.x project: a minor bump
(`0.x`) carries new features, a patch bump (`0.x.y`) carries fixes.

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

[0.4.0]: https://github.com/paradoxcomputer/zonescan/releases/tag/v0.4.0
[0.3.0]: https://github.com/paradoxcomputer/zonescan/releases/tag/v0.3.0
