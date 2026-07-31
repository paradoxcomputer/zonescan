//! Durable storage for decoded sequencer block/tx data, backed by **redb**
//! (pure-Rust embedded KV - keeps the tree C-free for cross-platform prebuilts
//! and the npx `cargo build` fallback).
//!
//! Layout (values are JSON-encoded; integer key parts are big-endian, and
//! block ids are stored *inverted* - `u64::MAX - block_id` - so a forward range
//! scan yields newest-first):
//!
//! - `txs`          hash+0+channel → TxRecord                (source of truth, dedup)
//! - `idx_feed`     inv(block_id)+tail → txkey               (global newest-first feed)
//! - `idx_channel`  channel+0+inv(block_id)+tail → txkey     (per-sequencer feed)
//! - `idx_account`  account+0+inv(block_id)+tail → txkey     (account fan-out)
//!
//! where `txkey`/`tail` are `hash+0+channel` (see [`tx_key`]). A tx hash covers program +
//! accounts + instruction data but NOT the channel, so two zones bootstrapped from the same
//! genesis config inscribe byte-identical txs that share a hash. Keying by hash alone made
//! the second zone's copy dedup into the first zone's record — silently hiding a whole
//! zone's genesis under another zone. The channel is part of the identity.
//! - `seq_summary`  channel → SeqTrack                       (per-sequencer state)
//! - `acct_bal`     account → AcctBal                        (L1 post-state balance)
//! - `meta`         "cursor:<channel>" → last L1 slot        (resume, no full re-scan)
//!
//! All writes for one batch go in a single write transaction so the primary rows
//! and every index commit atomically. Methods are synchronous (redb commits
//! fsync); callers run them via `spawn_blocking`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, LazyLock, RwLock};

use anyhow::Result;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{AcctBal, SeqTrack, TxRecord, MAX_PLAUSIBLE_BLOCK_ID};

const TXS: TableDefinition<&str, &[u8]> = TableDefinition::new("txs");
// NOTE: the block-ordered `idx_feed` table was removed — it was written on every tx but read
// nowhere (the global feed uses the time-ordered IDX_FEED_TIME below). Any rows an older build
// left on disk are harmless orphans.
const IDX_FEED_TIME: TableDefinition<&[u8], &str> = TableDefinition::new("idx_feed_time");
const IDX_CHANNEL: TableDefinition<&[u8], &str> = TableDefinition::new("idx_channel");
const IDX_ACCOUNT: TableDefinition<&[u8], &str> = TableDefinition::new("idx_account");
// per-(channel,program) index: key = "channel\0program\0" + inv(block) + hash, value = hash.
// Range-scan "channel\0program\0".."channel\0program\1" for O(limit) newest-first program txs
// and an exact total, replacing db.program()'s up-to-SCAN_CAP walk of the whole channel index.
// Keyed by the raw stored `program` string (name OR hex) so it stays consistent with the tx-row
// links and the /api/txs program filter; the commit() relabel path keeps it in sync.
const IDX_PROGRAM: TableDefinition<&[u8], &str> = TableDefinition::new("idx_program");
const SEQ_SUMMARY: TableDefinition<&str, &[u8]> = TableDefinition::new("seq_summary");
const ACCT_BAL: TableDefinition<&str, &[u8]> = TableDefinition::new("acct_bal");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const DEPLOY_ELF: TableDefinition<&str, &[u8]> = TableDefinition::new("deploy_elf");
// Token-name resolution learned from the chain (no sequencer RPC needed):
//   token_def     definition account -> "name\tsupply"   (from NewFungibleDefinition)
//   holding_def   holding/ATA account -> definition       (supply acct + ata Create ops)
const TOKEN_DEF: TableDefinition<&str, &str> = TableDefinition::new("token_def");
const HOLDING_DEF: TableDefinition<&str, &str> = TableDefinition::new("holding_def");
// owner account -> its token-holding accounts (ATAs). Key = "owner\0ata", value = definition;
// range-scan the "owner\0" prefix for all of an owner's holdings in O(#holdings). Built from ata
// Create ops [owner, definition, ata] at ingest — no store scan on the account page.
const OWNER_ATA: TableDefinition<&str, &str> = TableDefinition::new("owner_ata");
// token definition -> its holder ATAs. Key = "definition\0ata", value = owner; range-scan the
// "definition\0" prefix (paginated) for the token's holders. Built from ata Create ops at ingest.
const DEF_HOLDER: TableDefinition<&str, &str> = TableDefinition::new("def_holder");
// token program -> its definition accounts. Key = "program\0definition", value unused;
// range-scan the "program\0" prefix. Lets a transfer resolve its token by PROGRAM when
// neither account is a known holding (e.g. the ATA Create predates the scan window) -
// only when the program's definitions carry exactly ONE distinct name (see token_op).
const PROG_DEF: TableDefinition<&str, &str> = TableDefinition::new("prog_def");
const TOKEN_MAP_VERSION: u64 = 2; // v2: (re)populates prog_def from stored txs
// Bumped when the tx primary key changes shape. v1 = `hash+0+channel` (was a bare `hash`,
// which collided across zones with identical genesis txs — see the module docs).
const TX_KEY_VERSION: u64 = 1;
// Bumped when raw-inscription txs need re-timestamping for the recency-ordered global feed.
const RAW_TS_VERSION: u64 = 1;
// Bumped to rebuild the per-(channel,program) index from stored txs (backfill_program_index).
const PROG_IDX_VERSION: u64 = 1;

/// Resolved TYPE for each program image id: `id -> (name, confidence, verified)`. `verified` = a
/// registry / getProgramIds name (trusted, confidence 1.0); otherwise a classifier `≈` guess.
/// Published by [`set_program_kinds`] after each guess pass. Consulted by `is_token_program` /
/// `is_ata_program` (token learning + display) AND `rec_matches_type` (the feed's Type filter),
/// so a raw-hex program id resolves to its name EVERYWHERE — fixing "filter by token/amm/ata/…
/// shows nothing" (programs are stored by raw image id, so the bare `rec_type` is always
/// "program"). Process-global: exactly one store per process.
static PROGRAM_INFO: LazyLock<RwLock<HashMap<String, (String, f64, bool)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Publish resolved program types (verified registry names + classifier guesses) so the db side
/// resolves a raw image id to its name for type-filtering + token recognition. Call after a guess
/// refresh, then `relearn_tokens`.
pub fn set_program_kinds(info: HashMap<String, (String, f64, bool)>) {
    if let Ok(mut g) = PROGRAM_INFO.write() {
        *g = info;
    }
}

/// True when program id `p` resolves (verified, or a guess ≥ `min_conf`) to the name `want`.
fn program_name_is(p: &str, want: &str, min_conf: f64) -> bool {
    PROGRAM_INFO
        .read()
        .ok()
        .and_then(|g| g.get(p).map(|(n, c, v)| n.as_str() == want && (*v || *c >= min_conf)))
        .unwrap_or(false)
}

/// The resolved name for a program id (verified registry name or a classifier guess), if any.
fn program_name(p: &str) -> Option<String> {
    PROGRAM_INFO.read().ok().and_then(|g| g.get(p).map(|(n, _, _)| n.clone()))
}

/// The faucet enum {GenesisTransferVault, GenesisTransferDirect} is reused byte-for-byte by the
/// genesis-supply guests (faucet / genesis_supply / genesis_supply_bridge / …). Its variant-0
/// (GenesisTransferVault) hides the native amount behind an 8-word ProgramId + an embedded base58
/// recipient string, so no other decoder reaches it.
fn is_faucet_family(p: &str) -> bool {
    program_name(p).is_some_and(|n| n == "faucet" || n.starts_with("genesis_supply"))
}

/// Cap how many index entries a filtered/account scan will walk, so a rare
/// free-text match can't turn into an unbounded scan.
const SCAN_CAP: usize = 50_000;

/// Options for a (paginated) transaction-feed query.
#[derive(Default)]
pub struct FeedOpts<'a> {
    pub channel: Option<&'a str>,
    pub kind: Option<&'a str>,
    /// privacy-preserving operation subtype filter: shield / deshield / private-send
    pub subtype: Option<&'a str>,
    pub q: Option<&'a str>,
    /// include only txs whose computed type (visibility/program/op) is in this set
    pub types: Option<&'a [String]>,
    /// include only txs whose program is in this set
    pub programs: Option<&'a [String]>,
    /// hide txs whose program is in this set (e.g. clock)
    pub exclude: Option<&'a [String]>,
    /// pagination cursor: return txs strictly older than (timestamp, block_id, hash).
    /// The global feed orders by timestamp; a channel feed by block_id.
    /// pagination cursor `(timestamp, block_id, hash, channel)`. The channel is part of it
    /// because index tails are `hash+0+channel` — a bare hash would not land on the row.
    pub after: Option<(u64, u64, &'a str, &'a str)>,
    /// oldest-first instead of newest-first (reverse iteration + flipped cursor).
    pub oldest: bool,
    pub limit: usize,
}

pub struct Db {
    db: Arc<Database>,
}

fn inv(block_id: u64) -> [u8; 8] {
    (u64::MAX - block_id).to_be_bytes()
}

/// Composite key for IDX_PROGRAM: "channel\0program\0" + inv(block) + hash.
/// Primary key for a tx row: `hash + 0 + channel`.
///
/// Hash FIRST so a `hash\0`..`hash\1` range scan finds every zone carrying that hash, which
/// is what [`Store::get_tx`] needs (the `/api/tx/<hash>` route has no channel). Channel is
/// part of the key because the hash alone is not an identity: identical genesis txs on two
/// zones hash the same, and keying by hash let one zone's copy overwrite the other's.
fn tx_key(hash: &str, channel: &str) -> String {
    format!("{hash}\0{channel}")
}

/// The `hash+0+channel` tail shared by every index key, so index entries are unique per
/// (tx, zone) too. Without the channel, two zones' identical genesis txs collapse to one
/// index entry at the same block id — the same bug one level down.
fn idx_tail(hash: &str, channel: &str) -> Vec<u8> {
    let mut t = Vec::with_capacity(hash.len() + 1 + channel.len());
    t.extend_from_slice(hash.as_bytes());
    t.push(0);
    t.extend_from_slice(channel.as_bytes());
    t
}

fn prog_key(channel: &str, program: &str, iv: &[u8; 8], tail: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(channel.len() + program.len() + 10 + tail.len());
    k.extend_from_slice(channel.as_bytes());
    k.push(0);
    k.extend_from_slice(program.as_bytes());
    k.push(0);
    k.extend_from_slice(iv);
    k.extend_from_slice(tail);
    k
}

// Values are stored as self-describing JSON: it round-trips serde
// `skip_serializing_if` fields correctly (bincode does not) and tolerates future
// schema additions. Records are small, so the size overhead is irrelevant here.
fn de<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(serde_json::from_slice(bytes)?)
}

/// The tx's display "type" (mirrors the UI's txType): deploy / shield / deshield /
/// authenticated_transfer (public *and* private sends collapse here) / program name /
/// "public". Used by the multi-select Type filter.
fn rec_type(rec: &TxRecord) -> &str {
    if rec.kind == "raw" {
        return "raw"; // a non-block raw inscription (not public/private)
    }
    if rec.kind == "deploy" {
        return "deploy";
    }
    if rec.kind == "private" {
        return if rec.subtype == "shield" || rec.subtype == "deshield" {
            rec.subtype.as_str()
        } else {
            "authenticated_transfer"
        };
    }
    match rec.program.as_deref() {
        // an unresolved raw-hex program id is the generic "program" type
        Some(p) if p.len() >= 40 && p.bytes().all(|b| b.is_ascii_hexdigit()) => "program",
        Some(p) => p,
        None => "public",
    }
}

/// Does `rec` match the wanted feed Type `want`? Beyond the literal `rec_type`, a raw-hex program
/// id also matches its RESOLVED name (verified registry name or classifier `≈` guess), so the UI's
/// Type filter — which lists resolved / `≈` names — selects the right txs even though programs are
/// stored by raw image id (for which `rec_type` alone is always "program").
fn rec_matches_type(rec: &TxRecord, want: &str) -> bool {
    if rec_type(rec) == want {
        return true;
    }
    if let Some(p) = rec.program.as_deref() {
        if p.len() >= 40 && p.bytes().all(|b| b.is_ascii_hexdigit()) {
            return PROGRAM_INFO
                .read()
                .ok()
                .and_then(|g| g.get(p).map(|(n, _, _)| n.as_str() == want))
                .unwrap_or(false);
        }
    }
    false
}

/// The transferred amount (little-endian u128) for a public native or token Transfer,
/// else None - used by relabel_privacy() to replay account balances.
fn transfer_amount(t: &TxRecord) -> Option<i128> {
    let w = &t.instruction_data;
    let u128_le = |s: &[u32]| -> i128 { s.iter().enumerate().map(|(i, &x)| (x as i128) << (32 * i)).sum() };
    // resolve the program to a funding kind by name OR its raw rc3 id (some records
    // store the unresolved hex id, which the name match would otherwise miss).
    let kind = match t.program.as_deref()? {
        "authenticated_transfer" | "pinata" | "pinata_token"
        | "a96e088942d7fc09afc7b1db5221558c67f772ac8130d04df1c086dc07ab8b7b" // rc3 auth_transfer
        | "beba346bf12ae2105b301aa7af0f922d2d67891660c52a6bf30968facbc2aacf" // rc3 pinata
        | "2c50b34c3709ca40f2d3339d4282e516a8d5ea8324cbc900d55fc4fef9d9f4e4" // rc3 pinata_token
        | "d9a19237236822b1f8100576ebd19a19f74178f99e284c983a4ac44acbd5b472" // rc5 auth_transfer
        | "9b3c8c8b84a2cab7ee51fd9e30f528a3bb51ca54ab0904a5f1ba7693fe874bec" // rc5 pinata
        | "14a015ff3ee264a3805bd96cdbaa2a01fdaa92a748903d83e1f776b00036882f" // rc5 pinata_token
            => "native",
        "token"
        | "6d1ec77d426db847e2a37eb964b78d7870b89f17fc7f2537c0e50046bd8a8150" // rc3 token
        | "c4584a559312f876bbde4248b1daf95f6fc895a42171734d3ffd32940c0adf24" // rc5 token
            => "token",
        // a FOREIGN build named only by the classifier guess (its raw image id isn't a known
        // built-in): recognize it via the published PROGRAM_INFO map so its amount still decodes.
        // authenticated_transfer is a BARE u128 (no discriminant) — which is exactly why the
        // generic `[variant<=15, u128]` shape probe misses it: its leading word IS the amount.
        p if program_name_is(p, "authenticated_transfer", 0.6)
            || program_name_is(p, "pinata", 0.6)
            || program_name_is(p, "pinata_token", 0.6) =>
        {
            "native"
        }
        p if is_token_program(p) => "token",
        _ => return None,
    };
    match kind {
        // rc3/rc4 native transfer + pinata: the instruction IS a bare u128 (4 words, no
        // discriminant), the amount at offset 0.
        "native" if w.len() == 4 => Some(u128_le(&w[0..4])),
        // rc5 wraps native in an ENUM: Transfer is variant 0 with the u128 at offset 1
        // (`[0, u128]` = 5 words — the same shape as a token Transfer). A non-Transfer variant
        // (e.g. the 1-word CreateAccount `[1]`) carries no amount. Without this, a rc5 transfer
        // of 40 mis-reads `u128_le(w[0..4])` = 40<<32 = 171_798_691_840.
        "native" if w.len() == 5 && w[0] == 0 => Some(u128_le(&w[1..5])),
        // token Transfer (variant 0): instruction is [0, u128 amount]
        "token" if w.len() >= 5 && w[0] == 0 => Some(u128_le(&w[1..5])),
        _ => None,
    }
}

/// The amount to DISPLAY for a token/native op - broader than `transfer_amount` (which is
/// only the Transfer amount used for balance replay). Adds the token `NewFungibleDefinition`
/// total_supply (variant 1, the u128 AFTER the risc0-encoded name string) and Mint (5) /
/// Burn (4). Returned as the raw u128 string. Layout is identical across rc3/rc4/rc5.
fn token_display_amount(rec: &TxRecord) -> Option<String> {
    // native + token Transfer (variant 0) already handled by transfer_amount
    if let Some(a) = transfer_amount(rec) {
        return Some(a.to_string());
    }
    let prog = rec.program.as_deref().unwrap_or("");
    let w = &rec.instruction_data;
    // faucet-family GenesisTransferVault (variant 0): [disc, ProgramId(8w), base58 String, u128].
    // The native genesis amount is the TRAILING u128 (final 4 words) — hidden behind the ProgramId
    // + embedded recipient address, so the transfer/generic decoders never see it. Keyed to the
    // verified faucet/genesis_supply* name so a look-alike shape can't produce a spurious amount.
    if w.first().copied() == Some(0) && w.len() >= 14 && is_faucet_family(prog) {
        return Some(u128_le_at(w, w.len() - 4).to_string());
    }
    if !is_token_program(prog) {
        return None;
    }
    match w.first().copied() {
        // Mint{amount} (5) / Burn{amount} (4): u128 right after the variant tag
        Some(4 | 5) if w.len() >= 5 => Some(u128_le_at(w, 1).to_string()),
        // NewFungibleDefinition{name: String, total_supply: u128} (1): supply after the name.
        // e.g. [1, 4, <"BRNZ" packed>, 20000000, 0, 0, 0] -> name len 4 (1 word) -> supply @3.
        Some(1) => {
            let off = 1 + r0_str_words(w, 1);
            (w.len() >= off + 4).then(|| u128_le_at(w, off).to_string())
        }
        _ => None,
    }
}

fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(v)?)
}

// ---- offline token-name learning -----------------------------------------------------
// A token's name lives in its definition account, but a Transfer only carries the two
// holding (ATA) accounts. We learn name <- definition and holding <- definition directly
// from the on-chain instructions (no sequencer RPC), so transfers resolve their token name
// even when the sequencer is down.

// risc0 serializes a String as [len: u32][ceil(len/4) words], 4 little-endian bytes/word.
fn r0_string(w: &[u32], off: usize) -> String {
    let len = *w.get(off).unwrap_or(&0) as usize;
    let nw = len.div_ceil(4);
    let mut b = Vec::with_capacity(nw * 4);
    for i in 0..nw {
        let x = *w.get(off + 1 + i).unwrap_or(&0);
        for k in 0..4 {
            b.push(((x >> (8 * k)) & 0xff) as u8);
        }
    }
    b.truncate(len);
    String::from_utf8_lossy(&b).into_owned()
}
fn r0_str_words(w: &[u32], off: usize) -> usize {
    1 + (*w.get(off).unwrap_or(&0) as usize).div_ceil(4)
}
fn u128_le_at(w: &[u32], off: usize) -> u128 {
    (0..4).map(|i| (*w.get(off + i).unwrap_or(&0) as u128) << (32 * i)).sum()
}
fn is_token_program(p: &str) -> bool {
    matches!(
        p,
        "token"
            | "6d1ec77d426db847e2a37eb964b78d7870b89f17fc7f2537c0e50046bd8a8150" // rc3
            | "c4584a559312f876bbde4248b1daf95f6fc895a42171734d3ffd32940c0adf24" // rc5
    ) || program_name_is(p, "token", 0.6)
}
fn is_ata_program(p: &str) -> bool {
    matches!(
        p,
        "ata" | "e4870e1f7ef3df44a22bec5e00d03f7d6ad5fbca7a87a56b38be9d85e2b932a4" // rc5
    ) || program_name_is(p, "ata", 0.6)
}

// Token names are learned entirely from on-chain `NewFungibleDefinition` ops (TOKEN_DEF),
// so there is no hardcoded ticker table: a per-zone hardcode goes stale on every chain reset
// (the old ids were the dead 0101 GOLD/SILV/BRNZ definitions) and would mis-name accounts on
// a zone whose real definitions differ.

/// Token mappings a tx establishes:
///   (Some((definition, name, supply)) from a NewFungibleDefinition,
///    Some((holding, definition))      from its supply account or an ata Create).
fn token_mappings(rec: &TxRecord) -> (Option<(String, String, u128)>, Option<(String, String)>) {
    let prog = rec.program.as_deref().unwrap_or("");
    let w = &rec.instruction_data;
    let a = &rec.accounts;
    // token NewFungibleDefinition{name, total_supply} (variant 1); accounts [definition, supply]
    // - but some builds carry only the [definition] account (no separate supply holding), so
    // accept a single account too: still learn definition -> name (the supply map only when a
    // second account is present). Without this a 1-account def program (e.g. foreign dcbbfebc)
    // never has its token name learned, so its transfers can't resolve one.
    if is_token_program(prog) && w.first().copied() == Some(1) && !a.is_empty() {
        let name = r0_string(w, 1);
        let supply = u128_le_at(w, 1 + r0_str_words(w, 1));
        if !name.is_empty() {
            let supply_map = (a.len() >= 2).then(|| (a[1].clone(), a[0].clone()));
            return (Some((a[0].clone(), name, supply)), supply_map);
        }
    }
    // ata Create (variant 0); accounts [owner, definition, ata]
    if is_ata_program(prog) && w.first().copied() == Some(0) && a.len() >= 3 {
        return (None, Some((a[2].clone(), a[1].clone())));
    }
    (None, None)
}

/// From an ata Create (`[owner, definition, ata]`), the `(owner, ata, definition)` link — for the
/// owner→holdings index. Kept separate from `token_mappings` so its other callers are unaffected.
fn ata_owner_link(rec: &TxRecord) -> Option<(String, String, String)> {
    let prog = rec.program.as_deref().unwrap_or("");
    let w = &rec.instruction_data;
    let a = &rec.accounts;
    if is_ata_program(prog) && w.first().copied() == Some(0) && a.len() >= 3 {
        return Some((a[0].clone(), a[2].clone(), a[1].clone())); // (owner, ata, definition)
    }
    None
}

/// One token holding: an ATA account, its token definition + resolved name/supply, and (if known)
/// its balance. Balances come straight from the persisted `acct_bal` — no per-holding RPC.
#[derive(serde::Serialize)]
pub struct Holding {
    pub account: String,
    pub definition: String,
    pub name: String,
    pub supply: String,
    pub balance: Option<String>,
}

impl Db {
    /// Open (or create) the database at `path`.
    pub fn open(path: &Path) -> Result<Db> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let db = Database::create(path)?;
        let db = Db { db: Arc::new(db) };
        // FIRST: every other migration below reads or writes the derived indexes, so the
        // primary key has to be the current shape before any of them run.
        match db.migrate_tx_keys() {
            Ok(n) if n > 0 => eprintln!(
                "tx store: re-keyed {n} tx(s) by (hash, zone) — txs shared between zones no \
                 longer overwrite each other; any that were lost to the old key return on the \
                 next scan of their L1 slots"
            ),
            Ok(_) => {}
            Err(e) => eprintln!("warning: tx-key migration failed: {e:#}"),
        }
        if let Err(e) = db.ensure_time_index() {
            eprintln!("warning: could not build time-ordered feed index: {e:#}");
        }
        match db.migrate_raw_timestamps() {
            Ok(n) if n > 0 => eprintln!("raw-inscription feed: re-timestamped {n} record(s) so they order by recency (were hidden at timestamp 0)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: raw-timestamp migration failed: {e:#}"),
        }
        match db.backfill_token_mappings() {
            Ok(n) if n > 0 => eprintln!("token-name index: learned {n} token definition(s) from stored txs"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: token-name backfill failed: {e:#}"),
        }
        match db.backfill_program_index() {
            Ok(n) if n > 0 => eprintln!("per-program index: linked {n} tx(s) to their (channel, program)"),
            Ok(_) => {}
            Err(e) => eprintln!("warning: per-program index backfill failed: {e:#}"),
        }
        Ok(db)
    }

    /// Persist a batch in one transaction. Returns how many txs were new (not
    /// already stored), so the caller can keep an accurate total.
    pub fn commit(
        &self,
        recs: &[TxRecord],
        summaries: &[(String, SeqTrack)],
        cursors: &[(String, u64)],
        accts: &[(String, AcctBal)],
    ) -> Result<u64> {
        let mut new = 0u64;
        let w = self.db.begin_write()?;
        {
            let mut txs = w.open_table(TXS)?;
            let mut feed_time = w.open_table(IDX_FEED_TIME)?;
            let mut chan = w.open_table(IDX_CHANNEL)?;
            let mut acct = w.open_table(IDX_ACCOUNT)?;
            let mut prog = w.open_table(IDX_PROGRAM)?;
            let mut tdef = w.open_table(TOKEN_DEF)?;
            let mut hdef = w.open_table(HOLDING_DEF)?;
            let mut owner_ata = w.open_table(OWNER_ATA)?;
            let mut def_holder = w.open_table(DEF_HOLDER)?;
            let mut prog_def = w.open_table(PROG_DEF)?;
            for r in recs {
                if r.hash.is_empty() {
                    continue;
                }
                // learn token name <- definition <- holding from this op (idempotent, runs
                // even on a dedup re-scan so older token/ata ops get indexed too).
                let (def, hold) = token_mappings(r);
                if let Some((d, name, supply)) = def {
                    tdef.insert(d.as_str(), format!("{name}\t{supply}").as_str())?;
                    if let Some(p) = r.program.as_deref().filter(|p| !p.is_empty()) {
                        prog_def.insert(format!("{p}\0{d}").as_str(), "")?;
                    }
                }
                if let Some((h, d)) = hold {
                    hdef.insert(h.as_str(), d.as_str())?;
                }
                // owner->ATA + definition->holder links, from an ata Create (idempotent).
                if let Some((owner, ata, def)) = ata_owner_link(r) {
                    owner_ata.insert(format!("{owner}\0{ata}").as_str(), def.as_str())?;
                    def_holder.insert(format!("{def}\0{ata}").as_str(), owner.as_str())?;
                }
                // dedup - but if a re-scan now carries a field the stored record
                // predates (instruction_data / deploy fields added after it was first
                // persisted), rewrite the body in place (indexes are hash-keyed).
                // (needs_rewrite, old_program) — old_program kept so a relabel can re-key IDX_PROGRAM.
                let key = tx_key(&r.hash, &r.channel);
                let stored_needs_rewrite: Option<(bool, Option<String>)> =
                    match txs.get(key.as_str())? {
                        Some(g) => {
                            let s: TxRecord = de(g.value())?;
                            let needs = (s.instruction_data.is_empty()
                                && !r.instruction_data.is_empty())
                                || (s.deploy_program.is_empty() && !r.deploy_program.is_empty())
                                || (s.bytecode_len == 0 && r.bytecode_len > 0)
                                // re-label a program id a newer build now names (e.g. an
                                // rc3 store's raw-hex clock id -> "clock" under rc4)
                                || (r.program.as_deref().is_some_and(|p| !p.is_empty())
                                    && s.program.as_deref() != r.program.as_deref())
                                // backfill the privacy op subtype onto older records
                                || (!r.subtype.is_empty() && s.subtype != r.subtype)
                                // backfill the public balance (enables shield/deshield relabel)
                                || (s.pub_balance.is_none() && r.pub_balance.is_some());
                            Some((needs, s.program.clone()))
                        }
                        None => None,
                    };
                if let Some((needs, old_prog)) = stored_needs_rewrite {
                    if needs {
                        txs.insert(key.as_str(), ser(r)?.as_slice())?;
                        // keep IDX_PROGRAM consistent when the program label changed (block/hash
                        // are stable): drop the stale old-program key, add the new one.
                        let np = r.program.as_deref().filter(|p| !p.is_empty());
                        if np != old_prog.as_deref() {
                            let iv = inv(r.block_id);
                            let tail = idx_tail(&r.hash, &r.channel);
                            if let Some(op) = old_prog.as_deref().filter(|p| !p.is_empty()) {
                                prog.remove(prog_key(&r.channel, op, &iv, &tail).as_slice())?;
                            }
                            if let Some(p) = np {
                                prog.insert(prog_key(&r.channel, p, &iv, &tail).as_slice(),
                                    key.as_str())?;
                            }
                        }
                    }
                    continue;
                }
                new += 1;
                let body = ser(r)?;
                txs.insert(key.as_str(), body.as_slice())?;
                let iv = inv(r.block_id);
                let h = idx_tail(&r.hash, &r.channel);
                let h = h.as_slice();

                // time-ordered global feed: inv(timestamp)+inv(block_id)+hash+0+channel, so the
                // newest-by-wall-clock tx leads regardless of per-channel block ids.
                let it = inv(r.timestamp);
                let mut tk = Vec::with_capacity(16 + h.len());
                tk.extend_from_slice(&it);
                tk.extend_from_slice(&iv);
                tk.extend_from_slice(h);
                feed_time.insert(tk.as_slice(), key.as_str())?;

                let mut ck = Vec::with_capacity(r.channel.len() + 9 + h.len());
                ck.extend_from_slice(r.channel.as_bytes());
                ck.push(0);
                ck.extend_from_slice(&iv);
                ck.extend_from_slice(h);
                chan.insert(ck.as_slice(), key.as_str())?;

                // per-(channel,program) index for O(limit) program lookups + exact totals.
                if let Some(p) = r.program.as_deref().filter(|p| !p.is_empty()) {
                    prog.insert(prog_key(&r.channel, p, &iv, h).as_slice(), key.as_str())?;
                }

                for a in &r.accounts {
                    let mut ak = Vec::with_capacity(a.len() + 9 + h.len());
                    ak.extend_from_slice(a.as_bytes());
                    ak.push(0);
                    ak.extend_from_slice(&iv);
                    ak.extend_from_slice(h);
                    acct.insert(ak.as_slice(), key.as_str())?;
                }

                // Token-activity index: a token Transfer touches only the two ATAs, never the
                // token's definition account, so the token page (which lists account(definition))
                // would miss it. Resolve each ATA -> its definition (learned in HOLDING_DEF from
                // the ata Create) and index the tx under the definition too, reusing IDX_ACCOUNT so
                // the token page needs no change. Both ATAs of a transfer resolve to the same
                // definition -> one row (key includes hash+channel); skipped when the definition is
                // already one of the tx's own accounts (the loop above indexed it).
                if is_token_program(r.program.as_deref().unwrap_or("")) {
                    let mut seen = std::collections::HashSet::new();
                    for a in &r.accounts {
                        let d = match hdef.get(a.as_str())? {
                            Some(g) => g.value().to_string(),
                            None => continue,
                        };
                        if seen.insert(d.clone()) && !r.accounts.iter().any(|x| *x == d) {
                            let mut dk = Vec::with_capacity(d.len() + 9 + h.len());
                            dk.extend_from_slice(d.as_bytes());
                            dk.push(0);
                            dk.extend_from_slice(&iv);
                            dk.extend_from_slice(h);
                            acct.insert(dk.as_slice(), key.as_str())?;
                        }
                    }
                }
            }
            if !summaries.is_empty() {
                let mut t = w.open_table(SEQ_SUMMARY)?;
                for (ch, s) in summaries {
                    t.insert(ch.as_str(), ser(s)?.as_slice())?;
                }
            }
            if !cursors.is_empty() {
                let mut t = w.open_table(META)?;
                for (ch, slot) in cursors {
                    t.insert(format!("cursor:{ch}").as_str(), *slot)?;
                }
            }
            if !accts.is_empty() {
                let mut t = w.open_table(ACCT_BAL)?;
                for (a, b) in accts {
                    t.insert(a.as_str(), ser(b)?.as_slice())?;
                }
            }
        }
        w.commit()?;
        Ok(new)
    }

    /// Backfill the time-ordered feed index from the txs table if it's empty - a
    /// one-time migration for stores created before the index existed. Idempotent.
    pub fn ensure_time_index(&self) -> Result<()> {
        let need = {
            let r = self.db.begin_read()?;
            let n = r.open_table(TXS).map(|t| t.len().unwrap_or(0)).unwrap_or(0);
            let ni = r.open_table(IDX_FEED_TIME).map(|t| t.len().unwrap_or(0)).unwrap_or(0);
            n > 0 && ni == 0
        };
        if !need {
            return Ok(());
        }
        let w = self.db.begin_write()?;
        {
            let txs = w.open_table(TXS)?;
            let mut ti = w.open_table(IDX_FEED_TIME)?;
            for item in txs.iter()? {
                let (_k, body) = item?;
                let rec: TxRecord = de(body.value())?;
                let tail = idx_tail(&rec.hash, &rec.channel);
                let mut tk = Vec::with_capacity(16 + tail.len());
                tk.extend_from_slice(&inv(rec.timestamp));
                tk.extend_from_slice(&inv(rec.block_id));
                tk.extend_from_slice(&tail);
                ti.insert(tk.as_slice(), tx_key(&rec.hash, &rec.channel).as_str())?;
            }
        }
        w.commit()?;
        Ok(())
    }

    /// One-time migration for stores whose tx rows are keyed by a bare `hash`.
    ///
    /// Those stores are also missing every tx that was silently deduped away by the old key
    /// (a zone whose genesis matched an earlier zone's), and no key rewrite can invent rows
    /// that were never written — those return on the next scan of their L1 slots. What this
    /// does is make the on-disk shape correct: re-key every surviving row as
    /// `hash+0+channel` and rebuild the derived indexes so their keys and values agree with
    /// it. Rebuilding beats patching entry-by-entry: the indexes are pure functions of the
    /// tx rows, so a rebuild cannot leave a half-migrated mix behind.
    ///
    /// Guarded by a meta version, so it runs once. Returns how many rows were re-keyed.
    pub fn migrate_tx_keys(&self) -> Result<usize> {
        {
            let r = self.db.begin_read()?;
            if let Ok(m) = r.open_table(META) {
                if m.get("tx_key_version")?.map(|v| v.value()) == Some(TX_KEY_VERSION) {
                    return Ok(0);
                }
            }
        }
        // Read every row first: a redb table can't be mutated mid-iteration. Values are
        // self-describing JSON carrying both hash and channel, so the old key is not needed.
        let all: Vec<TxRecord> = {
            let r = self.db.begin_read()?;
            let mut v = Vec::new();
            if let Ok(txs) = r.open_table(TXS) {
                for item in txs.iter()? {
                    let (_k, body) = item?;
                    v.push(de::<TxRecord>(body.value())?);
                }
            }
            v
        };
        let w = self.db.begin_write()?;
        let mut n = 0usize;
        {
            let mut txs = w.open_table(TXS)?;
            let mut feed_time = w.open_table(IDX_FEED_TIME)?;
            let mut chan = w.open_table(IDX_CHANNEL)?;
            let mut acct = w.open_table(IDX_ACCOUNT)?;
            let mut prog = w.open_table(IDX_PROGRAM)?;
            txs.retain(|_, _| false)?;
            feed_time.retain(|_, _| false)?;
            chan.retain(|_, _| false)?;
            acct.retain(|_, _| false)?;
            prog.retain(|_, _| false)?;
            for rec in &all {
                if rec.hash.is_empty() {
                    continue;
                }
                let key = tx_key(&rec.hash, &rec.channel);
                txs.insert(key.as_str(), ser(rec)?.as_slice())?;
                let iv = inv(rec.block_id);
                let tail = idx_tail(&rec.hash, &rec.channel);

                let mut tk = Vec::with_capacity(16 + tail.len());
                tk.extend_from_slice(&inv(rec.timestamp));
                tk.extend_from_slice(&iv);
                tk.extend_from_slice(&tail);
                feed_time.insert(tk.as_slice(), key.as_str())?;

                let mut ck = Vec::with_capacity(rec.channel.len() + 9 + tail.len());
                ck.extend_from_slice(rec.channel.as_bytes());
                ck.push(0);
                ck.extend_from_slice(&iv);
                ck.extend_from_slice(&tail);
                chan.insert(ck.as_slice(), key.as_str())?;

                if let Some(p) = rec.program.as_deref().filter(|p| !p.is_empty()) {
                    prog.insert(prog_key(&rec.channel, p, &iv, &tail).as_slice(), key.as_str())?;
                }
                for a in &rec.accounts {
                    let mut ak = Vec::with_capacity(a.len() + 9 + tail.len());
                    ak.extend_from_slice(a.as_bytes());
                    ak.push(0);
                    ak.extend_from_slice(&iv);
                    ak.extend_from_slice(&tail);
                    acct.insert(ak.as_slice(), key.as_str())?;
                }
                // Replay the token-activity rows too (ATA -> definition), or the token page
                // would lose every transfer on rebuild: those rows are indexed under the
                // definition account, which is never one of the tx's own accounts.
                // HOLDING_DEF is not wiped here, so the same lookup the ingest path uses works.
                if is_token_program(rec.program.as_deref().unwrap_or("")) {
                    let hdef = w.open_table(HOLDING_DEF)?;
                    let mut seen = std::collections::HashSet::new();
                    for a in &rec.accounts {
                        let d = match hdef.get(a.as_str())? {
                            Some(g) => g.value().to_string(),
                            None => continue,
                        };
                        if seen.insert(d.clone()) && !rec.accounts.iter().any(|x| *x == d) {
                            let mut dk = Vec::with_capacity(d.len() + 9 + tail.len());
                            dk.extend_from_slice(d.as_bytes());
                            dk.push(0);
                            dk.extend_from_slice(&iv);
                            dk.extend_from_slice(&tail);
                            acct.insert(dk.as_slice(), key.as_str())?;
                        }
                    }
                }
                n += 1;
            }
            w.open_table(META)?.insert("tx_key_version", TX_KEY_VERSION)?;
        }
        w.commit()?;
        Ok(n)
    }

    /// One-time migration for stores written before raw txs carried a sortable timestamp.
    /// Such raw-inscription records were persisted with `timestamp == 0`, which sinks them
    /// below every block in the recency-ordered global feed (`inv(timestamp)`), so they
    /// vanish from the home page. Give each a real millisecond timestamp (its observation
    /// time, else now) and re-key its time-feed index entry from `inv(0)` to the new value.
    /// Guarded by a meta version, so it runs once. Returns how many records were fixed.
    pub fn migrate_raw_timestamps(&self) -> Result<usize> {
        {
            let r = self.db.begin_read()?;
            if let Ok(m) = r.open_table(META) {
                if m.get("raw_ts_version")?.map(|v| v.value()) == Some(RAW_TS_VERSION) {
                    return Ok(0);
                }
            }
        }
        // Collect the stale records first (read), then rewrite (write) - a redb table can't
        // be mutated mid-iteration.
        let stale: Vec<TxRecord> = {
            let r = self.db.begin_read()?;
            let mut v = Vec::new();
            if let Ok(txs) = r.open_table(TXS) {
                for item in txs.iter()? {
                    let (_k, body) = item?;
                    let rec: TxRecord = de(body.value())?;
                    if rec.kind == "raw" && rec.timestamp == 0 {
                        v.push(rec);
                    }
                }
            }
            v
        };
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let w = self.db.begin_write()?;
        {
            let mut txs = w.open_table(TXS)?;
            let mut feed_time = w.open_table(IDX_FEED_TIME)?;
            for mut rec in stale.iter().cloned() {
                let tail = idx_tail(&rec.hash, &rec.channel);
                let key = tx_key(&rec.hash, &rec.channel);
                // drop the stale inv(0)+inv(block_id)+tail time-index key
                let mut old = inv(0).to_vec();
                old.extend_from_slice(&inv(rec.block_id));
                old.extend_from_slice(&tail);
                feed_time.remove(old.as_slice())?;
                // observation time: seconds in seen_unix, millis in timestamp (block scale)
                let seen = if rec.seen_unix > 0 { rec.seen_unix } else { now };
                rec.seen_unix = seen;
                rec.timestamp = seen.saturating_mul(1000);
                txs.insert(key.as_str(), ser(&rec)?.as_slice())?;
                let mut tk = inv(rec.timestamp).to_vec();
                tk.extend_from_slice(&inv(rec.block_id));
                tk.extend_from_slice(&tail);
                feed_time.insert(tk.as_slice(), key.as_str())?;
            }
            let mut m = w.open_table(META)?;
            m.insert("raw_ts_version", RAW_TS_VERSION)?;
        }
        w.commit()?;
        Ok(stale.len())
    }

    /// Total number of stored transactions.
    pub fn tx_total(&self) -> u64 {
        (|| -> Result<u64> {
            let r = self.db.begin_read()?;
            match r.open_table(TXS) {
                Ok(t) => Ok(t.len()?),
                Err(_) => Ok(0),
            }
        })()
        .unwrap_or(0)
    }

    /// One transaction by hash, optionally pinned to a zone.
    ///
    /// The same hash can legitimately exist on SEVERAL zones (identical genesis txs), so a
    /// bare-hash lookup scans the `hash\0` prefix. With `channel` set the matching zone's row
    /// wins; without one — or when that zone doesn't carry it — the first row is returned so
    /// an unscoped `/api/tx/<hash>` link still resolves instead of 404ing.
    pub fn get_tx_on(&self, hash: &str, channel: Option<&str>) -> Result<Option<TxRecord>> {
        if hash.is_empty() {
            return Ok(None);
        }
        let r = self.db.begin_read()?;
        let t = match r.open_table(TXS) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        // exact hit first: avoids the scan on the common (zone-scoped) path.
        if let Some(ch) = channel.filter(|c| !c.is_empty()) {
            if let Some(g) = t.get(tx_key(hash, ch).as_str())? {
                return Ok(Some(de(g.value())?));
            }
        }
        // `hash\0` .. `hash\u{1}` brackets exactly this hash's rows across every zone.
        let lo = format!("{hash}\0");
        let hi = format!("{hash}\u{1}");
        let mut first = None;
        for item in t.range::<&str>(lo.as_str()..hi.as_str())? {
            let (_k, v) = item?;
            let rec: TxRecord = de(v.value())?;
            if channel.is_some_and(|c| !c.is_empty() && rec.channel == c) {
                return Ok(Some(rec));
            }
            if first.is_none() {
                first = Some(rec);
            }
        }
        Ok(first)
    }


    fn matches(rec: &TxRecord, o: &FeedOpts) -> bool {
        if let Some(k) = o.kind {
            if rec.kind != k {
                return false;
            }
        }
        if let Some(types) = o.types {
            if !types.iter().any(|x| rec_matches_type(rec, x)) {
                return false;
            }
        }
        if let Some(st) = o.subtype {
            if rec.subtype != st {
                return false;
            }
        }
        if let Some(ps) = o.programs {
            if !rec.program.as_deref().is_some_and(|p| ps.iter().any(|x| x == p)) {
                return false;
            }
        }
        if let Some(ex) = o.exclude {
            if rec.program.as_deref().is_some_and(|p| ex.iter().any(|x| x == p)) {
                return false;
            }
        }
        if let Some(q) = o.q {
            let q = q.to_lowercase();
            let hay = format!(
                "{} {} {} {} {}",
                rec.hash,
                rec.channel,
                rec.program.clone().unwrap_or_default(),
                rec.accounts.join(" "),
                rec.block_id
            )
            .to_lowercase();
            if !hay.contains(&q) {
                return false;
            }
        }
        true
    }

    /// The highest plausible sequencer block on `channel` whose L1 inscription slot is at or
    /// below `lib` (the L1 last-irreversible slot) - i.e. the block id that should read "final".
    /// Walks the channel index newest-first (block ids descending) and returns the first block
    /// whose stored L1 slot <= lib; since block ids and L1 slots increase together, that first
    /// match from the top IS the maximum finalized block. Skips raw inscriptions and undecodable
    /// (garbage-id) rows. Bounded by the "finalizing" band above lib (the finality lag in blocks).
    ///
    /// This is the fix for the frozen-`finalized_block_id` bug: the ingest paths only mark a
    /// block final if its slot was already <= lib when first observed, and live blocks always
    /// arrive above lib - so nothing promoted them as lib advanced. Recomputing from the stored
    /// per-block slots heals both the live case and any accumulated backlog.
    pub fn finalized_block_for(&self, channel: &str, lib: u64) -> Result<Option<u64>> {
        let r = self.db.begin_read()?;
        let idx = match r.open_table(IDX_CHANNEL) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        let txs = match r.open_table(TXS) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        let mut prefix0 = channel.as_bytes().to_vec();
        prefix0.push(0);
        let mut hi = channel.as_bytes().to_vec();
        hi.push(1);
        let mut scanned = 0usize;
        for item in idx.range(prefix0.as_slice()..hi.as_slice())? {
            let (_, v) = item?;
            let Some(g) = txs.get(v.value())? else { continue };
            let rec: TxRecord = de(g.value())?;
            // a raw inscription or an undecodable block carries a garbage block id / no real
            // slot - never let it set the finalized frontier.
            if rec.kind == "raw" || rec.block_id >= MAX_PLAUSIBLE_BLOCK_ID {
                continue;
            }
            if rec.slot.is_some_and(|s| s <= lib) {
                return Ok(Some(rec.block_id));
            }
            scanned += 1;
            if scanned >= SCAN_CAP {
                break;
            }
        }
        Ok(None)
    }

    /// Resolve which token an account belongs to from the on-chain mappings learned at
    /// ingest (no sequencer RPC). `account` may be a definition or a holding/ATA. Returns
    /// (definition, name, supply).
    pub fn resolve_token(&self, account: &str) -> Option<(String, String, String)> {
        let r = self.db.begin_read().ok()?;
        let tdef = r.open_table(TOKEN_DEF).ok()?;
        let unpack = |v: &str| {
            let (name, supply) = v.split_once('\t').unwrap_or((v, ""));
            (name.to_string(), supply.to_string())
        };
        // account is itself a token definition
        if let Some(g) = tdef.get(account).ok()? {
            let (name, supply) = unpack(g.value());
            return Some((account.to_string(), name, supply));
        }
        // account is a holding -> its definition -> name
        let hdef = r.open_table(HOLDING_DEF).ok()?;
        let definition = hdef.get(account).ok()??.value().to_string();
        match tdef.get(definition.as_str()).ok()? {
            Some(g) => {
                let (name, supply) = unpack(g.value());
                Some((definition, name, supply))
            }
            // learned holding->definition, but its name hasn't been learned yet
            None => None,
        }
    }

    /// An account's token holdings: the ATAs it owns (via the owner→ATA index) plus, if the account
    /// is itself an ATA, its own token. Each holding resolves its token name/supply + persisted
    /// balance via O(1) map lookups — no store scan, no per-holding RPC. Capped so a pathological
    /// owner can't blow up the response.
    pub fn token_holdings(&self, account: &str) -> Vec<Holding> {
        const CAP: usize = 200;
        let mut out: Vec<Holding> = Vec::new();
        let Ok(r) = self.db.begin_read() else {
            return out;
        };
        // 1. account as OWNER -> each of its ATAs (range the "account\0" prefix).
        if let Ok(t) = r.open_table(OWNER_ATA) {
            let lo = format!("{account}\0");
            let hi = format!("{account}\u{1}");
            if let Ok(it) = t.range(lo.as_str()..hi.as_str()) {
                for (k, v) in it.flatten() {
                    if let Some(ata) = k.value().split('\0').nth(1) {
                        let def = v.value().to_string();
                        let (name, supply) =
                            self.resolve_token(&def).map(|(_, n, s)| (n, s)).unwrap_or_default();
                        out.push(Holding {
                            // token balance is account STATE (parse_token_holding via RPC), not the
                            // native `acct_bal`; the serve layer fills it in.
                            balance: None,
                            account: ata.to_string(),
                            definition: def,
                            name,
                            supply,
                        });
                        if out.len() >= CAP {
                            break;
                        }
                    }
                }
            }
        }
        // 2. account IS an ATA -> its own token holding (if not already covered above).
        if out.iter().all(|h| h.account != account) {
            if let Some((definition, name, supply)) = self.resolve_token(account) {
                if !name.is_empty() && definition != account {
                    out.push(Holding {
                        balance: None, // token balance filled from RPC by the serve layer
                        account: account.to_string(),
                        definition,
                        name,
                        supply,
                    });
                }
            }
        }
        out
    }

    /// Holders of a token (paginated), via the definition→holder index. `after` = the last holder
    /// ATA of the previous page (exclusive) for infinite scroll. Balances are filled by the serve
    /// layer (RPC). O(limit) index reads — no store scan.
    pub fn token_holders(&self, definition: &str, after: Option<&str>, limit: usize) -> Vec<Holding> {
        use std::ops::Bound;
        let mut out: Vec<Holding> = Vec::new();
        let Ok(r) = self.db.begin_read() else {
            return out;
        };
        let Ok(t) = r.open_table(DEF_HOLDER) else {
            return out;
        };
        let (name, supply) =
            self.resolve_token(definition).map(|(_, n, s)| (n, s)).unwrap_or_default();
        let lo = after
            .map(|a| format!("{definition}\0{a}"))
            .unwrap_or_else(|| format!("{definition}\0"));
        let hi = format!("{definition}\u{1}");
        let lo_b = if after.is_some() {
            Bound::Excluded(lo.as_str())
        } else {
            Bound::Included(lo.as_str())
        };
        if let Ok(it) = t.range::<&str>((lo_b, Bound::Excluded(hi.as_str()))) {
            for (k, _) in it.flatten() {
                if let Some(ata) = k.value().split('\0').nth(1) {
                    out.push(Holding {
                        balance: None,
                        account: ata.to_string(),
                        definition: definition.to_string(),
                        name: name.clone(),
                        supply: supply.clone(),
                    });
                    if out.len() >= limit {
                        break;
                    }
                }
            }
        }
        out
    }

    /// For a token / ATA / native transfer, the (amount, token_name) to render in the feed
    /// and tx page (e.g. "250", "GOLD"). Amount is decoded from `instruction_data`; the name
    /// is resolved from any account (a definition, or a holding -> definition) via the
    /// on-chain-learned maps. Either may be `None`.
    pub fn token_op(&self, rec: &TxRecord) -> (Option<String>, Option<String>) {
        let prog = rec.program.as_deref().unwrap_or("");
        let amount = token_display_amount(rec);
        let name = if is_token_program(prog) || is_ata_program(prog) {
            rec.accounts
                .iter()
                .find_map(|a| {
                    self.resolve_token(a).map(|(_, n, _)| n).filter(|n| !n.is_empty())
                })
                // no account link (e.g. the ATA Create predates the scan window): fall
                // back to the PROGRAM's own definitions - safe only when they carry
                // exactly one distinct name, so no multi-token program is mislabeled.
                .or_else(|| self.program_token_name(prog))
        } else {
            None
        };
        (amount, name)
    }

    /// The single distinct token name defined by `program`, when unambiguous: resolves
    /// each learned definition (`prog_def`) through `token_def` and returns the name
    /// only if exactly one distinct non-empty name exists; `None` for zero or several.
    fn program_token_name(&self, program: &str) -> Option<String> {
        if program.is_empty() {
            return None;
        }
        let r = self.db.begin_read().ok()?;
        let pd = r.open_table(PROG_DEF).ok()?;
        let tdef = r.open_table(TOKEN_DEF).ok()?;
        let lo = format!("{program}\0");
        let hi = format!("{program}\u{1}");
        let mut name: Option<String> = None;
        for (k, _) in pd.range(lo.as_str()..hi.as_str()).ok()?.flatten() {
            let Some(def) = k.value().split('\0').nth(1) else { continue };
            let Ok(Some(v)) = tdef.get(def) else { continue };
            let n = v.value().split('\t').next().unwrap_or("");
            if n.is_empty() {
                continue;
            }
            match &name {
                Some(seen) if seen != n => return None, // several tokens: ambiguous
                _ => name = Some(n.to_string()),
            }
        }
        name
    }

    /// If `account` is a known token's definition or a holding of one, its (symbol, role) -
    /// role is "definition" (the account IS the token definition) or "holding" (a holding
    /// whose definition resolves to that symbol). Used to label WHICH account produced a
    /// token tag in the tx-detail accounts list, so the tag is visibly sourced.
    pub fn account_token(&self, account: &str) -> Option<(String, String)> {
        let (definition, name, _supply) = self.resolve_token(account)?;
        if name.is_empty() {
            return None;
        }
        let role = if definition == account { "definition" } else { "holding" };
        Some((name, role.to_string()))
    }

    /// Persist a token mapping learned from the sequencer RPC, so later lookups are offline.
    pub fn learn_token(&self, holding: &str, definition: &str, name: &str, supply: &str) -> Result<()> {
        let w = self.db.begin_write()?;
        {
            let mut tdef = w.open_table(TOKEN_DEF)?;
            let mut hdef = w.open_table(HOLDING_DEF)?;
            if !name.is_empty() {
                tdef.insert(definition, format!("{name}\t{supply}").as_str())?;
            }
            if !holding.is_empty() && holding != definition {
                hdef.insert(holding, definition)?;
            }
        }
        w.commit()?;
        Ok(())
    }

    /// Re-scan every stored tx and (re)populate the offline token-name maps (`token_def` /
    /// `holding_def`). UNGATED, so it re-runs whenever the fingerprint-recognized token/ata set
    /// changes (see [`set_program_kinds`]) - that is what lets FOREIGN-build token programs, named
    /// only by the classifier's `≈token`/`≈ata` guess, get their `NewFungibleDefinition` names +
    /// ATA links learned, so transfers resolve their token name OFFLINE (e.g. on L1-read-only
    /// channels with no sequencer RPC). Returns the definition count learned.
    pub fn relearn_tokens(&self) -> Result<usize> {
        let mut defs: Vec<(String, String)> = Vec::new();
        let mut prog_defs: Vec<(String, String)> = Vec::new(); // (program, definition)
        let mut holds: Vec<(String, String)> = Vec::new();
        let mut atas: Vec<(String, String, String)> = Vec::new(); // (owner, ata, definition)
        // token ops (hash, block, accounts) to link into the token-activity index (see commit()).
        let mut token_recs: Vec<(String, u64, Vec<String>)> = Vec::new();
        {
            let r = self.db.begin_read()?;
            if let Ok(txs) = r.open_table(TXS) {
                for item in txs.iter()? {
                    let (_, v) = item?;
                    let rec: TxRecord = de(v.value())?;
                    let (def, hold) = token_mappings(&rec);
                    if let Some((d, name, supply)) = def {
                        if let Some(p) = rec.program.as_deref().filter(|p| !p.is_empty()) {
                            prog_defs.push((p.to_string(), d.clone()));
                        }
                        defs.push((d, format!("{name}\t{supply}")));
                    }
                    if let Some((h, d)) = hold {
                        holds.push((h, d));
                    }
                    if let Some(link) = ata_owner_link(&rec) {
                        atas.push(link);
                    }
                    if is_token_program(rec.program.as_deref().unwrap_or("")) && !rec.hash.is_empty()
                    {
                        token_recs.push((rec.hash.clone(), rec.block_id, rec.accounts.clone()));
                    }
                }
            }
        }
        let n = defs.len();
        if defs.is_empty() && holds.is_empty() && atas.is_empty() {
            return Ok(0);
        }
        // ata/holding -> definition, so token transfers can be linked to their definition.
        let ata2def: std::collections::HashMap<&str, &str> =
            holds.iter().map(|(h, d)| (h.as_str(), d.as_str())).collect();
        let w = self.db.begin_write()?;
        {
            let mut tdef = w.open_table(TOKEN_DEF)?;
            let mut hdef = w.open_table(HOLDING_DEF)?;
            let mut owner_ata = w.open_table(OWNER_ATA)?;
            let mut def_holder = w.open_table(DEF_HOLDER)?;
            let mut prog_def = w.open_table(PROG_DEF)?;
            for (d, v) in &defs {
                tdef.insert(d.as_str(), v.as_str())?;
            }
            for (p, d) in &prog_defs {
                prog_def.insert(format!("{p}\0{d}").as_str(), "")?;
            }
            for (h, d) in &holds {
                hdef.insert(h.as_str(), d.as_str())?;
            }
            for (owner, ata, def) in &atas {
                owner_ata.insert(format!("{owner}\0{ata}").as_str(), def.as_str())?;
                def_holder.insert(format!("{def}\0{ata}").as_str(), owner.as_str())?;
            }
            // backfill the token-activity index (idempotent; mirrors the live path in commit()).
            let mut acct = w.open_table(IDX_ACCOUNT)?;
            for (hash, block, accounts) in &token_recs {
                let iv = inv(*block);
                let h = hash.as_bytes();
                let mut seen = std::collections::HashSet::new();
                for a in accounts {
                    let Some(d) = ata2def.get(a.as_str()).copied() else {
                        continue;
                    };
                    if seen.insert(d) && !accounts.iter().any(|x| x == d) {
                        let mut dk = Vec::with_capacity(d.len() + 9 + h.len());
                        dk.extend_from_slice(d.as_bytes());
                        dk.push(0);
                        dk.extend_from_slice(&iv);
                        dk.extend_from_slice(h);
                        acct.insert(dk.as_slice(), hash.as_str())?;
                    }
                }
            }
        }
        w.commit()?;
        Ok(n)
    }

    /// One-time backfill: populate the token-name maps from stored txs so tokens indexed before
    /// this feature resolve offline too. Version-gated (runs once); ongoing + foreign-program
    /// re-learning goes through [`Db::relearn_tokens`].
    pub fn backfill_token_mappings(&self) -> Result<usize> {
        {
            let r = self.db.begin_read()?;
            if let Ok(m) = r.open_table(META) {
                if m.get("token_map_version")?.map(|v| v.value()) == Some(TOKEN_MAP_VERSION) {
                    return Ok(0);
                }
            }
        }
        let n = self.relearn_tokens()?;
        let w = self.db.begin_write()?;
        {
            let mut m = w.open_table(META)?;
            m.insert("token_map_version", TOKEN_MAP_VERSION)?;
        }
        w.commit()?;
        Ok(n)
    }

    /// One-time backfill of the per-(channel,program) index from stored txs, so program lookups
    /// on a store created before this index resolve in O(limit) too. Version-gated (runs once).
    /// Idempotent: keys are (channel,program,block,hash), so re-inserting is a no-op.
    pub fn backfill_program_index(&self) -> Result<usize> {
        {
            let r = self.db.begin_read()?;
            if let Ok(m) = r.open_table(META) {
                if m.get("prog_idx_version")?.map(|v| v.value()) == Some(PROG_IDX_VERSION) {
                    return Ok(0);
                }
            }
        }
        // collect (channel, program, block, hash) in a read txn, then write (can't mutate a
        // table mid-iteration; write the separate IDX_PROGRAM after the TXS scan completes).
        let mut rows: Vec<(String, String, u64, String)> = Vec::new();
        {
            let r = self.db.begin_read()?;
            if let Ok(txs) = r.open_table(TXS) {
                for item in txs.iter()? {
                    let (_, v) = item?;
                    let rec: TxRecord = de(v.value())?;
                    if rec.hash.is_empty() {
                        continue;
                    }
                    if let Some(p) = rec.program.as_deref().filter(|p| !p.is_empty()) {
                        rows.push((rec.channel, p.to_string(), rec.block_id, rec.hash));
                    }
                }
            }
        }
        let n = rows.len();
        let w = self.db.begin_write()?;
        {
            let mut prog = w.open_table(IDX_PROGRAM)?;
            for (channel, program, block, hash) in &rows {
                let iv = inv(*block);
                prog.insert(
                    prog_key(channel, program, &iv, hash.as_bytes()).as_slice(),
                    hash.as_str(),
                )?;
            }
            let mut m = w.open_table(META)?;
            m.insert("prog_idx_version", PROG_IDX_VERSION)?;
        }
        w.commit()?;
        Ok(n)
    }

    /// Newest-first transaction feed: scoped to a channel, filtered by kind /
    /// free-text / program include+exclude, and paginated via the `after` cursor.
    pub fn feed(&self, o: &FeedOpts) -> Result<Vec<TxRecord>> {
        let r = self.db.begin_read()?;
        let txs = match r.open_table(TXS) {
            Ok(t) => t,
            Err(_) => return Ok(vec![]),
        };
        let mut out = Vec::new();
        let mut scanned = 0usize;
        let take = |hash: &str, out: &mut Vec<TxRecord>| -> Result<bool> {
            if let Some(g) = txs.get(hash)? {
                let rec: TxRecord = de(g.value())?;
                if Self::matches(&rec, o) {
                    out.push(rec);
                }
            }
            Ok(out.len() >= o.limit)
        };

        use std::ops::Bound;
        if let Some(ch) = o.channel {
            let idx = match r.open_table(IDX_CHANNEL) {
                Ok(t) => t,
                Err(_) => return Ok(vec![]),
            };
            let mut prefix0 = ch.as_bytes().to_vec();
            prefix0.push(0);
            let mut hi = ch.as_bytes().to_vec();
            hi.push(1);
            let cursor = o.after.map(|(_, bid, h, c)| {
                let mut k = ch.as_bytes().to_vec();
                k.push(0);
                k.extend_from_slice(&inv(bid));
                k.extend_from_slice(&idx_tail(h, c));
                k
            });
            if o.oldest {
                // oldest-first: reverse-iterate [prefix0, cursor); RangeTo excludes the cursor.
                let end = match &cursor {
                    Some(c) => Bound::Excluded(c.as_slice()),
                    None => Bound::Excluded(hi.as_slice()),
                };
                for item in idx
                    .range::<&[u8]>((Bound::Included(prefix0.as_slice()), end))?
                    .rev()
                {
                    let (_, v) = item?;
                    if take(v.value(), &mut out)? || scanned >= SCAN_CAP {
                        break;
                    }
                    scanned += 1;
                }
            } else {
                let start = cursor.clone().unwrap_or_else(|| prefix0.clone());
                for item in idx.range(start.as_slice()..hi.as_slice())? {
                    let (k, v) = item?;
                    if cursor.as_deref().is_some_and(|c| k.value() == c) {
                        continue; // skip the cursor row itself
                    }
                    if take(v.value(), &mut out)? || scanned >= SCAN_CAP {
                        break;
                    }
                    scanned += 1;
                }
            }
        } else {
            // global feed: ordered by timestamp (inv(ts)+inv(block)+hash).
            let idx = match r.open_table(IDX_FEED_TIME) {
                Ok(t) => t,
                Err(_) => return Ok(vec![]),
            };
            let cursor = o.after.map(|(ts, bid, h, c)| {
                let mut k = inv(ts).to_vec();
                k.extend_from_slice(&inv(bid));
                k.extend_from_slice(&idx_tail(h, c));
                k
            });
            if o.oldest {
                // oldest-first: reverse-iterate (.., cursor); cursor excluded.
                let end = match &cursor {
                    Some(c) => Bound::Excluded(c.as_slice()),
                    None => Bound::Unbounded,
                };
                for item in idx.range::<&[u8]>((Bound::Unbounded, end))?.rev() {
                    let (_, v) = item?;
                    if take(v.value(), &mut out)? || scanned >= SCAN_CAP {
                        break;
                    }
                    scanned += 1;
                }
            } else {
                let start: Vec<u8> = cursor.clone().unwrap_or_default();
                for item in idx.range(start.as_slice()..)? {
                    let (k, v) = item?;
                    if cursor.as_deref().is_some_and(|c| k.value() == c) {
                        continue;
                    }
                    if take(v.value(), &mut out)? || scanned >= SCAN_CAP {
                        break;
                    }
                    scanned += 1;
                }
            }
        }
        Ok(out)
    }

    /// Resolve shield vs deshield for privacy txs from the public account's balance
    /// direction (the only observable signal - amounts are ZK-hidden). For each public
    /// account, walk its privacy txs oldest-first: the first public-touching op is a
    /// shield (you must deposit before you can withdraw); after that a fallen balance =>
    /// shield, a risen balance => deshield. Returns how many subtypes changed.
    pub fn relabel_privacy(&self) -> Result<usize> {
        use std::collections::BTreeMap;
        // Gather all txs per channel - public transfers carry the balances needed to
        // reconstruct an account's pre-state, so single-privacy-tx accounts resolve too
        // (not only ones with a prior privacy tx to diff against).
        let mut by_chan: BTreeMap<String, Vec<TxRecord>> = BTreeMap::new();
        {
            let r = self.db.begin_read()?;
            let txs = match r.open_table(TXS) {
                Ok(t) => t,
                Err(_) => return Ok(0),
            };
            for item in txs.iter()? {
                let (_, v) = item?;
                let rec: TxRecord = de(v.value())?;
                by_chan.entry(rec.channel.clone()).or_default().push(rec);
            }
        }
        // keyed by the COMPOSITE tx key: the same hash can exist on several zones, and this
        // replay is per-zone, so a bare hash would relabel the wrong zone's row.
        let mut updates: Vec<(String, &'static str)> = Vec::new();
        for (_chan, mut txs) in by_chan {
            txs.sort_by_key(|t| t.block_id);
            // Replay the channel in block order, tracking each account's public balance.
            // Transfers move funds sender->recipient; each privacy tx's post-state is
            // authoritative, so shield (balance fell) vs deshield (rose) is the delta vs
            // the tracked pre-balance.
            let mut bal: BTreeMap<String, i128> = BTreeMap::new();
            for t in &txs {
                if t.kind == "private" {
                    let (Some(acct), Some(post)) = (
                        t.accounts.first(),
                        t.pub_balance.as_deref().and_then(|b| b.parse::<i128>().ok()),
                    ) else {
                        continue;
                    };
                    // untracked account starts at 0 - a shield needs prior public funds,
                    // so a fresh account whose balance went up must be a deshield (a
                    // withdraw/receive into public), while a debit is a shield.
                    let pre = bal.get(acct).copied().unwrap_or(0);
                    let sub = if post > pre { "deshield" } else { "shield" };
                    updates.push((tx_key(&t.hash, &t.channel), sub));
                    bal.insert(acct.clone(), post); // authoritative post-state
                } else if t.kind == "public" {
                    if let Some(amt) = transfer_amount(t) {
                        if t.accounts.len() >= 2 {
                            *bal.entry(t.accounts[0].clone()).or_insert(0) -= amt;
                            let last = t.accounts[t.accounts.len() - 1].clone();
                            *bal.entry(last).or_insert(0) += amt;
                        }
                    }
                }
            }
        }
        if updates.is_empty() {
            return Ok(0);
        }
        // subtype isn't indexed, so rewriting the record body is enough.
        let w = self.db.begin_write()?;
        let mut n = 0usize;
        {
            let mut t = w.open_table(TXS)?;
            for (key, sub) in updates {
                let cur: Option<TxRecord> = match t.get(key.as_str())? {
                    Some(g) => Some(de(g.value())?),
                    None => None,
                };
                if let Some(mut rec) = cur {
                    if rec.subtype != sub {
                        rec.subtype = sub.to_string();
                        let body = ser(&rec)?;
                        t.insert(key.as_str(), body.as_slice())?;
                        n += 1;
                    }
                }
            }
        }
        w.commit()?;
        Ok(n)
    }

    /// An account's transactions (newest-first), optionally scoped to one channel,
    /// plus the per-channel breakdown across all of its txs and the scoped total.
    #[allow(clippy::too_many_arguments)]
    pub fn account(
        &self,
        id: &str,
        scope: Option<&str>,
        after: Option<(u64, &str, &str)>,
        kind: Option<&str>,
        types: Option<&[String]>,
        oldest: bool,
        limit: usize,
    ) -> Result<(Vec<TxRecord>, usize, Vec<(String, String, usize)>)> {
        use std::ops::Bound;
        let r = self.db.begin_read()?;
        let txs = match r.open_table(TXS) {
            Ok(t) => t,
            Err(_) => return Ok((vec![], 0, vec![])),
        };
        let idx = match r.open_table(IDX_ACCOUNT) {
            Ok(t) => t,
            Err(_) => return Ok((vec![], 0, vec![])),
        };
        let mut prefix0 = id.as_bytes().to_vec();
        prefix0.push(0);
        let mut hi = id.as_bytes().to_vec();
        hi.push(1);
        // pagination: on a cursor page, start just after it and skip the (full-scan)
        // per-channel breakdown + total - those are only needed for the first page.
        let cursor = after.map(|(bid, h, c)| {
            let mut k = id.as_bytes().to_vec();
            k.push(0);
            k.extend_from_slice(&inv(bid));
            k.extend_from_slice(&idx_tail(h, c));
            k
        });
        let paged = cursor.is_some();
        // visibility (kind) + computed-type filter - the same predicate the main feed uses.
        let pass = |rec: &TxRecord| -> bool {
            if let Some(k) = kind {
                if rec.kind != k {
                    return false;
                }
            }
            if let Some(ts) = types {
                if !ts.iter().any(|x| rec_matches_type(rec, x)) {
                    return false;
                }
            }
            true
        };
        let mut out = Vec::new();
        let mut total = 0usize;
        let mut per: std::collections::BTreeMap<String, (String, usize)> =
            std::collections::BTreeMap::new();
        let mut scanned = 0usize;
        // shared per-record handling for the newest- and oldest-first scans: the per-channel
        // breakdown counts every tx (first page only); the list + total honor scope + filter.
        // `break`s the enclosing loop once a paged page fills.
        macro_rules! handle {
            ($hash:expr) => {{
                if let Some(g) = txs.get($hash)? {
                    let rec: TxRecord = de(g.value())?;
                    if !paged {
                        per.entry(rec.channel.clone())
                            .or_insert_with(|| (rec.channel_short.clone(), 0))
                            .1 += 1;
                    }
                    if scope.is_none_or(|c| c == rec.channel) && pass(&rec) {
                        total += 1;
                        if out.len() < limit {
                            out.push(rec);
                        } else if paged {
                            break;
                        }
                    }
                }
            }};
        }
        if oldest {
            // oldest-first: reverse-iterate [prefix0, cursor); the cursor row is excluded.
            let end = match &cursor {
                Some(c) => Bound::Excluded(c.as_slice()),
                None => Bound::Excluded(hi.as_slice()),
            };
            for item in idx
                .range::<&[u8]>((Bound::Included(prefix0.as_slice()), end))?
                .rev()
            {
                if scanned >= SCAN_CAP {
                    break;
                }
                scanned += 1;
                let (_, v) = item?;
                handle!(v.value());
            }
        } else {
            let start = cursor.clone().unwrap_or_else(|| prefix0.clone());
            for item in idx.range(start.as_slice()..hi.as_slice())? {
                if scanned >= SCAN_CAP {
                    break;
                }
                scanned += 1;
                let (k, v) = item?;
                if cursor.as_deref().is_some_and(|c| k.value() == c) {
                    continue; // skip the cursor row itself
                }
                handle!(v.value());
            }
        }
        let channels = per.into_iter().map(|(c, (s, n))| (c, s, n)).collect();
        Ok((out, total, channels))
    }

    /// Transactions whose program matches `label` within a channel (newest-first), plus the exact
    /// total count of matches. Reads the per-(channel,program) index: O(limit) deserializes for the
    /// page, and an exact total from key iteration alone (no per-tx deserialize, no SCAN_CAP) —
    /// replacing the old walk of the whole channel index that both undercounted past 50k and paid
    /// a TxRecord deserialize for every tx in the channel.
    pub fn program(
        &self,
        channel: &str,
        label: &str,
        limit: usize,
    ) -> Result<(Vec<TxRecord>, usize)> {
        let r = self.db.begin_read()?;
        let txs = match r.open_table(TXS) {
            Ok(t) => t,
            Err(_) => return Ok((vec![], 0)),
        };
        let idx = match r.open_table(IDX_PROGRAM) {
            Ok(t) => t,
            Err(_) => return Ok((vec![], 0)),
        };
        // scope: "channel\0label\0" .. "channel\0label\1"
        let mut lo = channel.as_bytes().to_vec();
        lo.push(0);
        lo.extend_from_slice(label.as_bytes());
        lo.push(0);
        let mut hi = channel.as_bytes().to_vec();
        hi.push(0);
        hi.extend_from_slice(label.as_bytes());
        hi.push(1);
        let mut out = Vec::new();
        let mut total = 0usize;
        for item in idx.range(lo.as_slice()..hi.as_slice())? {
            let (_k, v) = item?;
            total += 1;
            if out.len() < limit {
                if let Some(g) = txs.get(v.value())? {
                    out.push(de(g.value())?);
                }
            }
        }
        Ok((out, total))
    }

    /// Aggregate recent public-tx invocation samples grouped by program id, for fingerprint
    /// classification. Walks the newest-first global feed up to `SCAN_CAP`, keeping at most
    /// `per_cap` samples per program (account ids + raw instruction words - the account list
    /// also feeds definition-account -> token-symbol attribution for guessed token programs).
    /// Clock txs are skipped (heartbeat noise). The classifier learns reference profiles from
    /// the programs it can already name and matches the rest against them.
    #[allow(clippy::type_complexity)]
    pub fn program_samples(
        &self,
        per_cap: usize,
    ) -> Result<Vec<(String, Vec<(Vec<String>, String, Vec<u32>)>)>> {
        use std::collections::HashMap;
        let r = self.db.begin_read()?;
        let txs = match r.open_table(TXS) {
            Ok(t) => t,
            Err(_) => return Ok(vec![]),
        };
        let idx = match r.open_table(IDX_FEED_TIME) {
            Ok(t) => t,
            Err(_) => return Ok(vec![]),
        };
        let mut by_prog: HashMap<String, Vec<(Vec<String>, String, Vec<u32>)>> = HashMap::new();
        let mut scanned = 0usize;
        for item in idx.range::<&[u8]>(..)? {
            if scanned >= SCAN_CAP {
                break;
            }
            scanned += 1;
            let (_k, v) = item?;
            let Some(g) = txs.get(v.value())? else { continue };
            let rec: TxRecord = de(g.value())?;
            // Only public txs carry an instruction to fingerprint.
            if rec.kind != "public" {
                continue;
            }
            let Some(prog) = rec.program.as_deref() else { continue };
            let e = by_prog.entry(prog.to_string()).or_default();
            if e.len() < per_cap {
                e.push((rec.accounts.clone(), rec.kind.clone(), rec.instruction_data.clone()));
            }
        }
        Ok(by_prog.into_iter().collect())
    }

    /// Read a `u64` meta value (e.g. the backfill low-water `backfill:floor:<node>`).
    pub fn get_meta_u64(&self, key: &str) -> Option<u64> {
        (|| -> Result<Option<u64>> {
            let r = self.db.begin_read()?;
            let t = match r.open_table(META) {
                Ok(t) => t,
                Err(_) => return Ok(None),
            };
            Ok(t.get(key)?.map(|g| g.value()))
        })()
        .ok()
        .flatten()
    }

    /// Set a `u64` meta value in its own transaction. Used to advance the backfill
    /// low-water mark *after* a chunk's records have committed, so an interrupted
    /// backfill re-scans (dedup-safe) rather than skipping a range on resume.
    pub fn set_meta_u64(&self, key: &str, val: u64) -> Result<()> {
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(META)?;
            t.insert(key, val)?;
        }
        w.commit()?;
        Ok(())
    }

    /// Persist deployed guest ELFs (deployment tx hash -> bytecode), deduped.
    pub fn put_elfs(&self, elfs: &[(String, Vec<u8>)]) -> Result<()> {
        if elfs.is_empty() {
            return Ok(());
        }
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(DEPLOY_ELF)?;
            for (h, b) in elfs {
                if !h.is_empty() && t.get(h.as_str())?.is_none() {
                    t.insert(h.as_str(), b.as_slice())?;
                }
            }
        }
        w.commit()?;
        Ok(())
    }

    /// The deployed guest ELF for a deployment tx hash, if stored.
    pub fn get_elf(&self, hash: &str) -> Option<Vec<u8>> {
        (|| -> Result<Option<Vec<u8>>> {
            let r = self.db.begin_read()?;
            let t = match r.open_table(DEPLOY_ELF) {
                Ok(t) => t,
                Err(_) => return Ok(None),
            };
            Ok(t.get(hash)?.map(|g| g.value().to_vec()))
        })()
        .ok()
        .flatten()
    }

    /// L1 post-state balance for an account (fallback when no sequencer RPC).
    pub fn acct_bal(&self, id: &str) -> Option<AcctBal> {
        (|| -> Result<Option<AcctBal>> {
            let r = self.db.begin_read()?;
            let t = match r.open_table(ACCT_BAL) {
                Ok(t) => t,
                Err(_) => return Ok(None),
            };
            match t.get(id)? {
                Some(g) => Ok(Some(de(g.value())?)),
                None => Ok(None),
            }
        })()
        .ok()
        .flatten()
    }

    /// Restore per-sequencer summaries + per-channel scan cursors from disk.
    pub fn restore(&self) -> Result<(Vec<(String, SeqTrack)>, Vec<(String, u64)>)> {
        let r = self.db.begin_read()?;
        let mut summaries = Vec::new();
        if let Ok(t) = r.open_table(SEQ_SUMMARY) {
            for item in t.iter()? {
                let (k, v) = item?;
                if let Ok(st) = de::<SeqTrack>(v.value()) {
                    summaries.push((k.value().to_string(), st));
                }
            }
        }
        let mut cursors = Vec::new();
        if let Ok(t) = r.open_table(META) {
            for item in t.iter()? {
                let (k, v) = item?;
                if let Some(ch) = k.value().strip_prefix("cursor:") {
                    cursors.push((ch.to_string(), v.value()));
                }
            }
        }
        Ok((summaries, cursors))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that mutate the process-global PROGRAM_INFO (set_program_kinds) so the
    /// default parallel test runner can't race them.
    static GLOBAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn token_mappings_learns_name_offline() {
        // MED0707 NewFungibleDefinition (variant 1, name len 7, supply 1_000_000)
        let w = vec![1u32, 7, 809780557, 3616823, 1_000_000, 0, 0, 0];
        assert_eq!(r0_string(&w, 1), "MED0707");
        let mut t = rec("h1", "ch", 1, Some("token"));
        t.instruction_data = w;
        t.accounts = vec!["DEF".into(), "SUPPLY".into()];
        assert_eq!(
            token_mappings(&t),
            (Some(("DEF".into(), "MED0707".into(), 1_000_000)), Some(("SUPPLY".into(), "DEF".into())))
        );
        // ata Create (variant 0): accounts [owner, definition, ata] -> ata maps to def
        let mut a = rec("h2", "ch", 1, Some("ata"));
        a.instruction_data = vec![0u32];
        a.accounts = vec!["OWNER".into(), "DEF".into(), "ATA".into()];
        assert_eq!(token_mappings(&a).1, Some(("ATA".into(), "DEF".into())));
        // 1-account NewFungibleDefinition (some builds carry only [definition], no supply):
        // still learn definition -> name, with no supply map (the live dcbbfebc case).
        let mut one = rec("h3", "ch", 1, Some("token"));
        one.instruction_data = vec![1u32, 7, 809780557, 3616823, 1_000_000, 0, 0, 0];
        one.accounts = vec!["DEFONLY".into()];
        assert_eq!(
            token_mappings(&one),
            (Some(("DEFONLY".into(), "MED0707".into(), 1_000_000)), None)
        );
    }

    /// BUG 1 fix: a FOREIGN-build token/ata program (image id unknown to the built-in match) is
    /// mined for token mappings ONLY after the classifier's `≈token`/`≈ata` guess is published
    /// via `set_program_kinds` - so L1-read-only channels resolve token names with no RPC.
    #[test]
    fn fingerprinted_foreign_token_program_learns_offline() {
        use std::collections::HashMap;
        let _g = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let ftoken = "dcbbfebcd59399961ed9973b8307dc475fd4c5ca5779aacfe7588f7dbc3f4a71"; // foreign token
        let fata = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // foreign ata
        // NewFungibleDefinition (variant 1, name len 7 "MED0707", supply 1_000_000)
        let mut t = rec("h1", "ch", 1, Some(ftoken));
        t.instruction_data = vec![1u32, 7, 809780557, 3616823, 1_000_000, 0, 0, 0];
        t.accounts = vec!["DEF".into(), "SUPPLY".into()];
        let mut a = rec("h2", "ch", 1, Some(fata));
        a.instruction_data = vec![0u32];
        a.accounts = vec!["OWNER".into(), "DEF".into(), "ATA".into()];
        // before publishing the fingerprint, foreign ids aren't recognized -> nothing learned.
        assert_eq!(token_mappings(&t), (None, None));
        assert_eq!(token_mappings(&a), (None, None));
        // publish the classifier's verdict; now the same ops mine their mappings.
        set_program_kinds(HashMap::from([
            (ftoken.to_string(), ("token".to_string(), 0.9, false)),
            (fata.to_string(), ("ata".to_string(), 0.9, false)),
        ]));
        assert_eq!(
            token_mappings(&t),
            (Some(("DEF".into(), "MED0707".into(), 1_000_000)), Some(("SUPPLY".into(), "DEF".into())))
        );
        assert_eq!(token_mappings(&a).1, Some(("ATA".into(), "DEF".into())));
        set_program_kinds(HashMap::new()); // reset the process-global for other tests
    }

    /// A transfer whose accounts have no learned ATA/holding link still resolves its token
    /// NAME through the program's own definitions - but only while the program has exactly
    /// one distinct token name (a second, differently-named definition turns it ambiguous).
    #[test]
    fn transfer_resolves_token_by_program_when_unambiguous() {
        use std::collections::HashMap;
        let _g = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = std::env::temp_dir().join(format!("zs-progdef-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();
        let ftoken = "ed01f2f48533fae789e7c51e756c422b5e5aa75df601aaf5042d74c5bba92778";
        set_program_kinds(HashMap::from([(ftoken.to_string(), ("token".to_string(), 0.9, false))]));
        // NewFungibleDefinition (variant 1, name len 7 "MED0707", supply 1_000_000)
        let mut def = rec("d1", "ch", 1, Some(ftoken));
        def.instruction_data = vec![1u32, 7, 809780557, 3616823, 1_000_000, 0, 0, 0];
        def.accounts = vec!["DEF".into(), "SUPPLY".into()];
        db.commit(&[def], &[], &[], &[]).unwrap();
        // transfer between two accounts with NO holding->definition link learned
        let mut tr = rec("t1", "ch", 2, Some(ftoken));
        tr.instruction_data = vec![0u32, 1, 0, 0, 0];
        tr.accounts = vec!["UNLINKED_A".into(), "UNLINKED_B".into()];
        let (amount, name) = db.token_op(&tr);
        assert_eq!(amount.as_deref(), Some("1"));
        assert_eq!(name.as_deref(), Some("MED0707"), "resolved via the program's sole definition");
        // a second definition with a DIFFERENT name makes the program ambiguous -> None
        let mut def2 = rec("d2", "ch", 3, Some(ftoken));
        def2.instruction_data = vec![1u32, 7, 809780557, 3616824, 1_000_000, 0, 0, 0]; // "MED0807"-ish
        def2.accounts = vec!["DEF2".into(), "SUPPLY2".into()];
        db.commit(&[def2], &[], &[], &[]).unwrap();
        assert_eq!(db.token_op(&tr).1, None, "two distinct names: no program-level guess");
        set_program_kinds(HashMap::new());
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    /// BUG 2 fix: `finalized_block_for` = highest plausible block whose L1 slot <= lib, so the
    /// reconciler can promote `finalized_block_id` as lib advances (raw/garbage rows ignored).
    #[test]
    fn finalized_block_for_promotes_up_to_lib() {
        let path = std::env::temp_dir().join(format!("zs-finfor-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();
        // blocks 1..=5 on "ch", each inscribed at L1 slot blk*10 (via the `rec` helper).
        let recs: Vec<TxRecord> = (1..=5)
            .map(|b| rec(&format!("h{b}"), "ch", b, Some("authenticated_transfer")))
            .collect();
        db.commit(&recs, &[], &[], &[]).unwrap();
        // lib between block 3 (slot 30) and block 4 (slot 40) -> highest final is block 3.
        assert_eq!(db.finalized_block_for("ch", 35).unwrap(), Some(3));
        // lib past the tip -> everything final; lib below the first slot -> nothing final.
        assert_eq!(db.finalized_block_for("ch", 1000).unwrap(), Some(5));
        assert_eq!(db.finalized_block_for("ch", 5).unwrap(), None);
        // a raw inscription (high block id, low slot) + a garbage undecodable id must NOT be
        // taken as the frontier even though they'd sort first with slot <= lib.
        let mut raw = rec("hraw", "ch", 100, Some("p"));
        raw.kind = "raw".into();
        raw.slot = Some(1);
        let mut garbage = rec("hgar", "ch", 6, Some("p"));
        garbage.block_id = 5_000_000_000_000; // >= MAX_PLAUSIBLE_BLOCK_ID (1e12)
        garbage.slot = Some(1);
        db.commit(&[raw, garbage], &[], &[], &[]).unwrap();
        assert_eq!(db.finalized_block_for("ch", 35).unwrap(), Some(3));
        let _ = std::fs::remove_file(&path);
    }

    /// BUG: the feed Type filter matched only rec_type, which is "program" for a raw-hex image id,
    /// so filtering by a resolved/guessed name (token/amm/…) returned nothing (programs are stored
    /// by raw id). rec_matches_type now also resolves the id via the published PROGRAM_INFO map.
    #[test]
    fn type_filter_matches_resolved_program_name() {
        use std::collections::HashMap;
        let _g = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = std::env::temp_dir().join(format!("zs-typefilter-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();
        let prog = "dcbbfebcd59399961ed9973b8307dc475fd4c5ca5779aacfe7588f7dbc3f4a71";
        let mut t = rec("h1", "ch", 1, Some(prog));
        t.instruction_data = vec![0, 1, 0, 0, 0];
        t.accounts = vec!["A".into(), "B".into()];
        db.commit(&[t], &[], &[], &[]).unwrap();
        let by = |ty: &str| {
            db.feed(&FeedOpts { types: Some(&[ty.to_string()]), limit: 10, ..Default::default() })
                .unwrap()
                .len()
        };
        // baseline: a raw-hex id is only the generic "program" type until we publish a name.
        set_program_kinds(HashMap::new());
        assert_eq!(by("token"), 0);
        assert_eq!(by("program"), 1);
        // publish the guess: "token" now selects it; "amm" doesn't; "program" still does.
        set_program_kinds(HashMap::from([(prog.to_string(), ("token".to_string(), 0.83, false))]));
        assert_eq!(by("token"), 1);
        assert_eq!(by("amm"), 0);
        assert_eq!(by("program"), 1);
        set_program_kinds(HashMap::new()); // reset global for other tests
        let _ = std::fs::remove_file(&path);
    }

    /// Review fix: a FOREIGN authenticated_transfer (BARE u128, no discriminant) named only by the
    /// classifier guess must still decode its amount — the generic `[variant<=15, u128]` shape
    /// probe can't, because its leading word IS the amount (usually > 15).
    #[test]
    fn foreign_authenticated_transfer_decodes_bare_u128_amount() {
        use std::collections::HashMap;
        let _g = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fauth = "66f6a58d92c159c3c13ea54d1e37a68a814f0fd3b8fd44b7d35c0617ac4456f8";
        let mut t = rec("h1", "ch", 1, Some(fauth));
        t.instruction_data = vec![15599007, 0, 0, 0]; // bare u128, 4 words, no discriminant
        t.accounts = vec!["SRC".into(), "DST".into()];
        // unrecognized until the guess is published -> no amount.
        set_program_kinds(HashMap::new());
        assert_eq!(transfer_amount(&t), None);
        // publish the ≈authenticated_transfer guess -> the bare u128 decodes.
        set_program_kinds(HashMap::from([(
            fauth.to_string(),
            ("authenticated_transfer".to_string(), 0.94, false),
        )]));
        assert_eq!(transfer_amount(&t), Some(15_599_007));
        set_program_kinds(HashMap::new());
    }

    /// Review fix: faucet-family GenesisTransferVault (variant 0) hides the native amount as the
    /// TRAILING u128 behind an 8-word ProgramId + an embedded base58 recipient string, so nothing
    /// decodes it. Keyed to the verified faucet/genesis_supply* name.
    #[test]
    fn faucet_genesis_vault_decodes_trailing_amount() {
        use std::collections::HashMap;
        let _g = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fp = "961277217aa4b6f77ba8fcceb2795247570d8560737f7eb7674cd5278170190c";
        // [0, ProgramId(8w), len=44 + 11-word string, u128 amount(4w)] = 25 words
        let mut w = vec![0u32];
        w.extend([10u32; 8]); // vault ProgramId
        w.push(44); // base58 recipient string length
        w.extend([0x4141_4141u32; 11]); // 44-byte address string
        w.extend([500_000u32, 0, 0, 0]); // trailing u128 amount
        assert_eq!(w.len(), 25);
        let mut t = rec("h1", "ch", 1, Some(fp));
        t.instruction_data = w;
        t.accounts = vec!["A".into(), "B".into()];
        // not recognized until the faucet name is published
        set_program_kinds(HashMap::new());
        assert_eq!(token_display_amount(&t), None);
        set_program_kinds(HashMap::from([(fp.to_string(), ("faucet".to_string(), 1.0, true))]));
        assert_eq!(token_display_amount(&t), Some("500000".to_string()));
        set_program_kinds(HashMap::new());
    }

    /// Review fix: rc5 authenticated_transfer is an ENUM — variant 0 Transfer = `[0, u128]` (amount
    /// at offset 1), NOT a bare u128 at offset 0 (which mis-read a transfer of 40 as 40<<32). A
    /// 1-word variant (create-account) carries no amount. rc3/rc4 bare-u128 stays offset 0.
    #[test]
    fn rc5_native_enum_transfer_amount() {
        let auth5 = "d9a19237236822b1f8100576ebd19a19f74178f99e284c983a4ac44acbd5b472"; // rc5
        let mut t = rec("h1", "ch", 1, Some(auth5));
        t.instruction_data = vec![0, 40, 0, 0, 0]; // variant 0 Transfer{40}
        t.accounts = vec!["S".into(), "R".into()];
        assert_eq!(transfer_amount(&t), Some(40)); // was 40<<32 = 171_798_691_840
        t.instruction_data = vec![1]; // variant 1 = create/register account
        t.accounts = vec!["A".into()];
        assert_eq!(transfer_amount(&t), None);
        // rc3/rc4 bare u128 (4 words) still reads the amount at offset 0
        let auth3 = "a96e088942d7fc09afc7b1db5221558c67f772ac8130d04df1c086dc07ab8b7b"; // rc3
        let mut u = rec("h2", "ch", 2, Some(auth3));
        u.instruction_data = vec![20_429_163, 0, 0, 0];
        assert_eq!(transfer_amount(&u), Some(20_429_163));
    }

    /// Token-holdings tab: an ATA Create `[owner, definition, ata]` indexes owner→ATA so the
    /// owner's holdings resolve to their token name via O(1) lookups; the ATA account itself
    /// resolves to a single holding.
    #[test]
    fn token_holdings_from_ata_creates() {
        let path = std::env::temp_dir().join(format!("zs-holdings-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();
        db.learn_token("", "GOLDDEF", "GOLD", "1000000").unwrap(); // token_def[GOLDDEF]=GOLD
        let mut c = rec("h1", "ch", 1, Some("ata")); // ata Create
        c.instruction_data = vec![0u32];
        c.accounts = vec!["WALLET".into(), "GOLDDEF".into(), "WALLET_GOLD_ATA".into()];
        db.commit(&[c], &[], &[], &[]).unwrap();
        // owner's holdings
        let h = db.token_holdings("WALLET");
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].account, "WALLET_GOLD_ATA");
        assert_eq!(h[0].name, "GOLD");
        assert_eq!(h[0].definition, "GOLDDEF");
        // the ATA itself resolves to its own single holding
        let h2 = db.token_holdings("WALLET_GOLD_ATA");
        assert_eq!(h2.len(), 1);
        assert_eq!(h2[0].name, "GOLD");
        // an unrelated account has no holdings
        assert!(db.token_holdings("nobody").is_empty());
        // holders of the token (def→holder index, paginated)
        let holders = db.token_holders("GOLDDEF", None, 50);
        assert_eq!(holders.len(), 1);
        assert_eq!(holders[0].account, "WALLET_GOLD_ATA");
        assert_eq!(holders[0].name, "GOLD");
        // cursor past the only holder -> empty page
        assert!(db.token_holders("GOLDDEF", Some("WALLET_GOLD_ATA"), 50).is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn token_transfer_indexed_under_definition() {
        // A token Transfer touches only the two ATAs, never the definition account; the token
        // page (which lists account(definition)) must still show it via the token-activity index.
        let path = std::env::temp_dir().join(format!("zs-tokacct-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();
        db.learn_token("", "GOLDDEF", "GOLD", "1000000").unwrap();
        // two ATA creates -> HOLDING_DEF learns A_ATA -> GOLDDEF and B_ATA -> GOLDDEF
        let mut ca = rec("ca", "ch", 1, Some("ata"));
        ca.instruction_data = vec![0u32];
        ca.accounts = vec!["A".into(), "GOLDDEF".into(), "A_ATA".into()];
        let mut cb = rec("cb", "ch", 2, Some("ata"));
        cb.instruction_data = vec![0u32];
        cb.accounts = vec!["B".into(), "GOLDDEF".into(), "B_ATA".into()];
        db.commit(&[ca, cb], &[], &[], &[]).unwrap();
        // a token Transfer between the two ATAs; the definition is NOT one of its accounts
        let mut t = rec("t1", "ch", 3, Some("token"));
        t.instruction_data = vec![0, 250, 0, 0, 0]; // Transfer(0){ amount = 250 }
        t.accounts = vec!["A_ATA".into(), "B_ATA".into()];
        db.commit(&[t], &[], &[], &[]).unwrap();
        // the token page for GOLDDEF now includes the ATA<->ATA transfer (live commit path)
        let (txs, _total, _ch) = db.account("GOLDDEF", None, None, None, None, false, 50).unwrap();
        assert!(txs.iter().any(|r| r.hash == "t1"), "transfer must appear on the token page");
        // relearn_tokens (the history/backfill path) is idempotent and keeps it present
        db.relearn_tokens().unwrap();
        let (txs2, _, _) = db.account("GOLDDEF", None, None, None, None, false, 50).unwrap();
        assert_eq!(txs2.iter().filter(|r| r.hash == "t1").count(), 1, "no duplicate rows");
        // the transfer never lands on an owner's own account page (it touched only the ATAs)
        let (owner, _, _) = db.account("A", None, None, None, None, false, 50).unwrap();
        assert!(owner.iter().all(|r| r.hash != "t1"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn program_index_query_count_and_relabel() {
        let path = std::env::temp_dir().join(format!("zs-progidx-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();
        let a = rec("pa", "ch", 1, Some("token"));
        let b = rec("pb", "ch", 2, Some("token"));
        let c = rec("pc", "ch", 3, Some("clock"));
        db.commit(&[a, b, c], &[], &[], &[]).unwrap();
        // exact total + O(limit) page, newest-first (block 2 before block 1)
        let (txs, total) = db.program("ch", "token", 50).unwrap();
        assert_eq!(total, 2);
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].hash, "pb");
        assert!(txs.iter().all(|t| t.program.as_deref() == Some("token")));
        assert_eq!(db.program("ch", "clock", 50).unwrap().1, 1);
        assert_eq!(db.program("ch", "nope", 50).unwrap().1, 0);
        // a limit smaller than the total still reports the exact total
        let (page, tot) = db.program("ch", "token", 1).unwrap();
        assert_eq!((page.len(), tot), (1, 2));
        // relabel: a rebuilt sequencer names a program a prior build stored as raw hex; the same
        // hash re-commits with a new `program`, so the old key must move to the new one.
        let c2 = rec("pc", "ch", 3, Some("clock_named"));
        db.commit(&[c2], &[], &[], &[]).unwrap();
        assert_eq!(db.program("ch", "clock", 50).unwrap().1, 0, "old key removed on relabel");
        assert_eq!(db.program("ch", "clock_named", 50).unwrap().1, 1, "new key added on relabel");
        let _ = std::fs::remove_file(&path);
    }

    fn rec(hash: &str, ch: &str, blk: u64, program: Option<&str>) -> TxRecord {
        let private = program.is_none();
        TxRecord {
            hash: hash.into(),
            kind: if private { "private".into() } else { "public".into() },
            subtype: if private { "private-send".into() } else { String::new() },
            program: program.map(|s| s.into()),
            accounts: vec!["acctA".into()],
            nullifiers: if private { vec!["n1".into()] } else { vec![] },
            commitments: vec![],
            encrypted_outputs: if private { Some(2) } else { None },
            pub_balance: None,
            instruction_data: if private { vec![] } else { vec![0, 42, 0, 0, 0] },
            deploy_program: String::new(),
            bytecode_len: 0,
            raw_payload: Vec::new(),
            block_id: blk,
            channel: ch.into(),
            channel_short: "ch".into(),
            slot: Some(blk * 10),
            timestamp: 1_700_000_000_000,
            seen_unix: 0,
        }
    }

    /// Two zones bootstrapped from the same genesis config inscribe BYTE-IDENTICAL txs, which
    /// therefore share a hash. Keying tx rows by hash alone made the second zone's copy dedup
    /// into the first's — one zone's genesis silently vanished, and its txs rendered under the
    /// other zone. Identity is (hash, channel); every read path must respect that.
    #[test]
    fn identical_tx_on_two_zones_is_kept_per_zone() {
        let path = std::env::temp_dir().join(format!("zs-samehash-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();

        // same hash, same block, same everything except the zone — the real genesis case.
        let a = rec("genesis1", "chanA", 1, Some("faucet"));
        let b = rec("genesis1", "chanB", 1, Some("faucet"));
        assert_eq!(
            db.commit(&[a, b], &[], &[], &[]).unwrap(),
            2,
            "both zones' copies must count as new; 1 means one overwrote the other"
        );

        // each zone's feed sees its own copy...
        for ch in ["chanA", "chanB"] {
            let f = db
                .feed(&FeedOpts { channel: Some(ch), limit: 10, ..Default::default() })
                .unwrap();
            assert_eq!(f.len(), 1, "zone {ch} lost its copy of the shared-hash tx");
            assert_eq!(f[0].channel, ch);
        }
        // ...and the global feed carries both, not one.
        let all = db.feed(&FeedOpts { limit: 10, ..Default::default() }).unwrap();
        assert_eq!(all.len(), 2, "global feed collapsed two distinct rows into one");

        // by-hash lookup resolves the requested zone, and still answers without one.
        for ch in ["chanA", "chanB"] {
            let got = db.get_tx_on("genesis1", Some(ch)).unwrap().expect("row for zone");
            assert_eq!(got.channel, ch, "asked for {ch}, got another zone's row");
        }
        let any = db.get_tx_on("genesis1", None).unwrap().expect("unscoped lookup resolves");
        assert!(any.channel == "chanA" || any.channel == "chanB");
        // an unknown zone falls back rather than 404ing an otherwise-valid hash
        assert!(db.get_tx_on("genesis1", Some("nope")).unwrap().is_some());

        // the account fan-out must not collapse either (both rows share acctA)
        let (rows, total, _by_chan) =
            db.account("acctA", None, None, None, None, false, 10).unwrap();
        assert_eq!(rows.len(), 2, "account view collapsed the two zones' rows");
        assert_eq!(total, 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn token_op_resolves_name_and_amount() {
        let path = std::env::temp_dir().join(format!("zs-tokop-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();
        let token = "c4584a559312f876bbde4248b1daf95f6fc895a42171734d3ffd32940c0adf24"; // rc5 token LE
        // Transfer{amount:250} (variant 0) touching a GOLD definition learned from the chain
        db.learn_token("", "GOLDDEF", "GOLD", "0").unwrap();
        let mut t = rec("h1", "ch", 1, Some(token));
        t.instruction_data = vec![0, 250, 0, 0, 0];
        t.accounts = vec!["GOLDDEF".into()];
        assert_eq!(db.token_op(&t), (Some("250".into()), Some("GOLD".into())));
        // learned holding -> definition -> name
        db.learn_token("HOLD1", "DEF1", "MED", "1000").unwrap();
        let mut u = rec("h2", "ch", 2, Some(token));
        u.instruction_data = vec![0, 7, 0, 0, 0];
        u.accounts = vec!["HOLD1".into()];
        assert_eq!(db.token_op(&u), (Some("7".into()), Some("MED".into())));
        // NewFungibleDefinition{name:"BRNZ", total_supply:20000000} (variant 1) - amount is the
        // supply, which sits AFTER the risc0 name string (the live-feed bug). Committing the op
        // learns BRNZ from the chain, so the name resolves without any hardcoded ticker table.
        let mut d = rec("h4", "ch", 4, Some(token));
        d.instruction_data = vec![1, 4, 1515082306, 20000000, 0, 0, 0]; // [var, len, "BRNZ", supply..]
        d.accounts = vec!["BRNZDEF".into()];
        db.commit(std::slice::from_ref(&d), &[], &[], &[]).unwrap();
        assert_eq!(db.token_op(&d), (Some("20000000".into()), Some("BRNZ".into())));
        // account_token labels WHICH account produced the tag + its role
        assert_eq!(
            db.account_token("GOLDDEF"),
            Some(("GOLD".into(), "definition".into()))
        );
        assert_eq!(db.account_token("HOLD1"), Some(("MED".into(), "holding".into())));
        assert_eq!(db.account_token("nope"), None);
        // a non-token public program: no amount, no token
        let n = rec("h3", "ch", 3, Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"));
        assert_eq!(db.token_op(&n), (None, None));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn relabel_shield_deshield_from_balance_delta() {
        let path = std::env::temp_dir().join(format!("zs-relabel-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();
        let mk = |hash: &str, blk: u64, bal: &str| TxRecord {
            hash: hash.into(),
            kind: "private".into(),
            subtype: "shield".into(),
            program: None,
            accounts: vec!["acctX".into()],
            nullifiers: vec!["n".into()],
            commitments: vec!["c".into()],
            encrypted_outputs: Some(1),
            pub_balance: Some(bal.into()),
            instruction_data: vec![],
            deploy_program: String::new(),
            bytecode_len: 0,
            raw_payload: Vec::new(),
            block_id: blk,
            channel: "ch".into(),
            channel_short: "ch".into(),
            slot: Some(blk * 10),
            timestamp: 1_700_000_000_000,
            seen_unix: 0,
        };
        // fund acctX publicly with 200, then it shields (200->100), then deshields (100->150)
        let fund = TxRecord {
            hash: "f0".into(),
            kind: "public".into(),
            subtype: String::new(),
            program: Some("authenticated_transfer".into()),
            accounts: vec!["src".into(), "acctX".into()],
            nullifiers: vec![],
            commitments: vec![],
            encrypted_outputs: None,
            pub_balance: None,
            instruction_data: vec![200, 0, 0, 0],
            deploy_program: String::new(),
            bytecode_len: 0,
            raw_payload: Vec::new(),
            block_id: 5,
            channel: "ch".into(),
            channel_short: "ch".into(),
            slot: Some(50),
            timestamp: 1_700_000_000_000,
            seen_unix: 0,
        };
        db.commit(&[fund, mk("s1", 10, "100"), mk("d1", 20, "150")], &[], &[], &[]).unwrap();
        let n = db.relabel_privacy().unwrap();
        assert!(n >= 1);
        assert_eq!(db.get_tx_on("s1", None).unwrap().unwrap().subtype, "shield"); // first op = deposit
        assert_eq!(db.get_tx_on("d1", None).unwrap().unwrap().subtype, "deshield"); // balance rose
    }

    #[test]
    fn relabel_seeds_pre_balance_from_public_transfer() {
        let path = std::env::temp_dir().join(format!("zs-relabel2-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();
        let tx = |hash: &str, blk: u64, kind: &str, prog: Option<&str>, accts: Vec<&str>, instr: Vec<u32>, bal: Option<&str>| TxRecord {
            hash: hash.into(),
            kind: kind.into(),
            subtype: if kind == "private" { "shield".into() } else { String::new() },
            program: prog.map(Into::into),
            accounts: accts.into_iter().map(Into::into).collect(),
            nullifiers: if kind == "private" { vec!["n".into()] } else { vec![] },
            commitments: if kind == "private" { vec!["c".into()] } else { vec![] },
            encrypted_outputs: if kind == "private" { Some(1) } else { None },
            pub_balance: bal.map(Into::into),
            instruction_data: instr,
            deploy_program: String::new(),
            bytecode_len: 0,
            raw_payload: Vec::new(),
            block_id: blk,
            channel: "ch".into(),
            channel_short: "ch".into(),
            slot: Some(blk * 10),
            timestamp: 1_700_000_000_000,
            seen_unix: 0,
        };
        // a public transfer credits "dst" with 10 (src -> dst), then dst's only privacy
        // tx posts a balance of 15 - rose 10->15, so it must be a deshield (withdraw),
        // even though it's dst's first privacy tx.
        db.commit(
            &[
                tx("p1", 5, "public", Some("authenticated_transfer"), vec!["src", "dst"], vec![10, 0, 0, 0], None),
                tx("v1", 6, "private", None, vec!["dst"], vec![], Some("15")),
            ],
            &[], &[], &[],
        ).unwrap();
        db.relabel_privacy().unwrap();
        assert_eq!(db.get_tx_on("v1", None).unwrap().unwrap().subtype, "deshield");
    }

    #[test]
    fn roundtrip_indexes_and_dedup() {
        let path = std::env::temp_dir().join(format!("zs-db-test-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();

        let recs = vec![
            rec("aa", "chan1", 5, Some("amm")),
            rec("bb", "chan1", 6, None), // private: program=None + skip fields (the bincode-breaking case)
        ];
        assert_eq!(db.commit(&recs, &[], &[], &[]).unwrap(), 2);

        // a private tx round-trips through JSON (would fail under bincode + skip_serializing_if)
        let got = db.get_tx_on("bb", None).unwrap().unwrap();
        assert_eq!(got.kind, "private");
        assert_eq!(got.program, None);
        assert_eq!(got.nullifiers, vec!["n1".to_string()]);
        assert_eq!(got.encrypted_outputs, Some(2));

        // global feed is newest-first (block 6 before block 5)
        let feed = db.feed(&FeedOpts { limit: 10, ..Default::default() }).unwrap();
        assert_eq!(feed.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["bb", "aa"]);

        // channel feed + kind filter + program include/exclude
        assert_eq!(db.feed(&FeedOpts { channel: Some("chan1"), limit: 10, ..Default::default() }).unwrap().len(), 2);
        assert_eq!(db.feed(&FeedOpts { kind: Some("private"), limit: 10, ..Default::default() }).unwrap().len(), 1);
        let amm = ["amm".to_string()];
        assert_eq!(db.feed(&FeedOpts { programs: Some(&amm), limit: 10, ..Default::default() }).unwrap().len(), 1);
        assert_eq!(db.feed(&FeedOpts { exclude: Some(&amm), limit: 10, ..Default::default() }).unwrap().len(), 1);

        // pagination: after the newest (bb, ts/block 6) returns the next page (aa)
        let pg = db.feed(&FeedOpts { after: Some((1_700_000_000_000, 6, "bb", "chan1")), limit: 10, ..Default::default() }).unwrap();
        assert_eq!(pg.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["aa"]);

        // oldest-first global + channel feeds are reversed (aa block 5 before bb block 6)
        let old = db.feed(&FeedOpts { oldest: true, limit: 10, ..Default::default() }).unwrap();
        assert_eq!(old.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["aa", "bb"]);
        let oldc = db.feed(&FeedOpts { channel: Some("chan1"), oldest: true, limit: 10, ..Default::default() }).unwrap();
        assert_eq!(oldc.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["aa", "bb"]);
        // oldest pagination: page 1 (limit 1) is aa; the next page (after aa) is the newer bb
        let op1 = db.feed(&FeedOpts { oldest: true, limit: 1, ..Default::default() }).unwrap();
        assert_eq!(op1.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["aa"]);
        let op2 = db.feed(&FeedOpts { oldest: true, after: Some((1_700_000_000_000, 5, "aa", "chan1")), limit: 10, ..Default::default() }).unwrap();
        assert_eq!(op2.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["bb"]);

        // computed-type filter: amm matches the public amm tx; "authenticated_transfer" matches the private send
        let ty_amm = ["amm".to_string()];
        assert_eq!(db.feed(&FeedOpts { types: Some(&ty_amm), limit: 10, ..Default::default() }).unwrap().len(), 1);
        let ty_tr = ["authenticated_transfer".to_string()];
        let trf = db.feed(&FeedOpts { types: Some(&ty_tr), limit: 10, ..Default::default() }).unwrap();
        assert_eq!(trf.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["bb"]);

        // account fan-out + breakdown
        let (atx, total, chans) = db.account("acctA", None, None, None, None, false, 10).unwrap();
        assert_eq!(total, 2);
        assert_eq!(atx.len(), 2);
        assert_eq!(chans.len(), 1);

        // dedup: re-committing the same records adds nothing
        assert_eq!(db.commit(&recs, &[], &[], &[]).unwrap(), 0);
        assert_eq!(db.tx_total(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn meta_u64_roundtrip() {
        let path = std::env::temp_dir().join(format!("zs-meta-test-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();

        // absent key reads as None; set then read back; overwrite wins
        assert_eq!(db.get_meta_u64("backfill:floor:node"), None);
        db.set_meta_u64("backfill:floor:node", 4200).unwrap();
        assert_eq!(db.get_meta_u64("backfill:floor:node"), Some(4200));
        db.set_meta_u64("backfill:floor:node", 800).unwrap();
        assert_eq!(db.get_meta_u64("backfill:floor:node"), Some(800));

        let _ = std::fs::remove_file(&path);
    }

    // A raw inscription persisted (old format) at timestamp 0 sinks to the bottom of the
    // recency-ordered global feed; the migration lifts it to a real millisecond timestamp so
    // it surfaces on the home page. Also confirms idempotency.
    #[test]
    fn raw_ts_migration_lifts_zero_timestamp_into_feed() {
        let path = std::env::temp_dir().join(format!("zs-rawts-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap(); // migration auto-runs (nothing stale), sets the guard

        let mut blk = rec("blk", "8888", 5, Some("token"));
        blk.timestamp = 1_700_000_000_000; // a real block, milliseconds
        let raw = TxRecord {
            hash: "raw1".into(),
            kind: "raw".into(),
            channel: "guest".into(),
            channel_short: "guest".into(),
            slot: Some(187085),
            raw_payload: vec![1, 2, 3],
            timestamp: 0, // the old, buried format
            seen_unix: 0,
            ..Default::default()
        };
        db.commit(&[blk, raw], &[], &[], &[]).unwrap();

        // before the fix: ts 0 sorts the raw tx to the very bottom of the global feed.
        let before = db.feed(&FeedOpts { limit: 10, ..Default::default() }).unwrap();
        assert_eq!(before.last().unwrap().hash, "raw1", "raw buried at timestamp 0");

        // force a re-run (open() already set the guard) and migrate.
        db.set_meta_u64("raw_ts_version", 0).unwrap();
        assert_eq!(db.migrate_raw_timestamps().unwrap(), 1, "one raw record fixed");

        let after = db.feed(&FeedOpts { limit: 10, ..Default::default() }).unwrap();
        let raw_after = after.iter().find(|r| r.hash == "raw1").unwrap();
        assert!(raw_after.timestamp > 0, "raw now carries a real timestamp");
        assert_eq!(after.first().unwrap().hash, "raw1", "sorts by recency (observation) now");
        // idempotent: the guard blocks a second pass.
        assert_eq!(db.migrate_raw_timestamps().unwrap(), 0);

        let _ = std::fs::remove_file(&path);
    }
}
