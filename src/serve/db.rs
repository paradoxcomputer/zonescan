//! Durable storage for decoded sequencer block/tx data, backed by **redb**
//! (pure-Rust embedded KV - keeps the tree C-free for cross-platform prebuilts
//! and the npx `cargo build` fallback).
//!
//! Layout (values are JSON-encoded; integer key parts are big-endian, and
//! block ids are stored *inverted* - `u64::MAX - block_id` - so a forward range
//! scan yields newest-first):
//!
//! - `txs`          hash → TxRecord                          (source of truth, dedup)
//! - `idx_feed`     inv(block_id)+hash → hash                (global newest-first feed)
//! - `idx_channel`  channel+0+inv(block_id)+hash → hash      (per-sequencer feed)
//! - `idx_account`  account+0+inv(block_id)+hash → hash      (account fan-out)
//! - `seq_summary`  channel → SeqTrack                       (per-sequencer state)
//! - `acct_bal`     account → AcctBal                        (L1 post-state balance)
//! - `meta`         "cursor:<channel>" → last L1 slot        (resume, no full re-scan)
//!
//! All writes for one batch go in a single write transaction so the primary rows
//! and every index commit atomically. Methods are synchronous (redb commits
//! fsync); callers run them via `spawn_blocking`.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::{AcctBal, SeqTrack, TxRecord};

const TXS: TableDefinition<&str, &[u8]> = TableDefinition::new("txs");
const IDX_FEED: TableDefinition<&[u8], &str> = TableDefinition::new("idx_feed");
const IDX_FEED_TIME: TableDefinition<&[u8], &str> = TableDefinition::new("idx_feed_time");
const IDX_CHANNEL: TableDefinition<&[u8], &str> = TableDefinition::new("idx_channel");
const IDX_ACCOUNT: TableDefinition<&[u8], &str> = TableDefinition::new("idx_account");
const SEQ_SUMMARY: TableDefinition<&str, &[u8]> = TableDefinition::new("seq_summary");
const ACCT_BAL: TableDefinition<&str, &[u8]> = TableDefinition::new("acct_bal");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const DEPLOY_ELF: TableDefinition<&str, &[u8]> = TableDefinition::new("deploy_elf");

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
    pub after: Option<(u64, u64, &'a str)>,
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

/// The transferred amount (little-endian u128) for a public native or token Transfer,
/// else None - used by relabel_privacy() to replay account balances.
fn transfer_amount(t: &TxRecord) -> Option<i128> {
    let w = &t.instruction_data;
    let u128_le = |s: &[u32]| -> i128 { s.iter().enumerate().map(|(i, &x)| (x as i128) << (32 * i)).sum() };
    // resolve the program to a funding kind by name OR its raw rc3 id (some records
    // store the unresolved hex id, which the name match would otherwise miss).
    let kind = match t.program.as_deref()? {
        "authenticated_transfer" | "pinata" | "pinata_token"
        | "89086ea909fcd742dbb1c7af8c552152ac72f7674dd03081dc86c0f17b8bab07" // rc3 auth_transfer
        | "6b34babe10e22af1a71a305b2d920faf1689672d6b2ac560fa6809f3cfaac2cb" // rc3 pinata
        | "4cb3502c40ca09379d33d3f216e5824283ead5a800c9cb24fec45fd5e4f4d9f9" // rc3 pinata_token
        | "3792a1d9b1226823760510f8199ad1ebf97841f7984c289e4ac44a3a72b4d5cb" // rc5 auth_transfer
        | "8b8c3c9bb7caa2849efd51eea328f53054ca51bba50409ab9376baf1ec4b87fe" // rc5 pinata
        | "ff15a014a364e23e6cd95b80012aaadba792aafd833d9048b076f7e12f883600" // rc5 pinata_token
            => "native",
        "token"
        | "7dc71e6d47b86d42b97ea3e2788db764179fb87037257ffc4600e5c050818abd" // rc3 token
        | "554a58c476f812934842debb5ff9dab1a495c86f4d7371219432fd3f24df0a0c" // rc5 token
            => "token",
        _ => return None,
    };
    match kind {
        // native transfer + pinata faucet: instruction is the u128 amount
        "native" if w.len() >= 4 => Some(u128_le(&w[0..4])),
        // token Transfer (variant 0): instruction is [0, u128 amount]
        "token" if w.len() >= 5 && w[0] == 0 => Some(u128_le(&w[1..5])),
        _ => None,
    }
}

fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(v)?)
}

impl Db {
    /// Open (or create) the database at `path`.
    pub fn open(path: &Path) -> Result<Db> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let db = Database::create(path)?;
        let db = Db { db: Arc::new(db) };
        if let Err(e) = db.ensure_time_index() {
            eprintln!("warning: could not build time-ordered feed index: {e:#}");
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
            let mut feed = w.open_table(IDX_FEED)?;
            let mut feed_time = w.open_table(IDX_FEED_TIME)?;
            let mut chan = w.open_table(IDX_CHANNEL)?;
            let mut acct = w.open_table(IDX_ACCOUNT)?;
            for r in recs {
                if r.hash.is_empty() {
                    continue;
                }
                // dedup - but if a re-scan now carries a field the stored record
                // predates (instruction_data / deploy fields added after it was first
                // persisted), rewrite the body in place (indexes are hash-keyed).
                let stored_needs_rewrite = match txs.get(r.hash.as_str())? {
                    Some(g) => {
                        let s: TxRecord = de(g.value())?;
                        Some(
                            (s.instruction_data.is_empty() && !r.instruction_data.is_empty())
                                || (s.deploy_program.is_empty() && !r.deploy_program.is_empty())
                                || (s.bytecode_len == 0 && r.bytecode_len > 0)
                                // re-label a program id a newer build now names (e.g. an
                                // rc3 store's raw-hex clock id -> "clock" under rc4)
                                || (r.program.as_deref().is_some_and(|p| !p.is_empty())
                                    && s.program.as_deref() != r.program.as_deref())
                                // backfill the privacy op subtype onto older records
                                || (!r.subtype.is_empty() && s.subtype != r.subtype)
                                // backfill the public balance (enables shield/deshield relabel)
                                || (s.pub_balance.is_none() && r.pub_balance.is_some()),
                        )
                    }
                    None => None,
                };
                if let Some(needs) = stored_needs_rewrite {
                    if needs {
                        txs.insert(r.hash.as_str(), ser(r)?.as_slice())?;
                    }
                    continue;
                }
                new += 1;
                let body = ser(r)?;
                txs.insert(r.hash.as_str(), body.as_slice())?;
                let iv = inv(r.block_id);
                let h = r.hash.as_bytes();

                let mut fk = Vec::with_capacity(8 + h.len());
                fk.extend_from_slice(&iv);
                fk.extend_from_slice(h);
                feed.insert(fk.as_slice(), r.hash.as_str())?;

                // time-ordered global feed: inv(timestamp)+inv(block_id)+hash, so the
                // newest-by-wall-clock tx leads regardless of per-channel block ids.
                let it = inv(r.timestamp);
                let mut tk = Vec::with_capacity(16 + h.len());
                tk.extend_from_slice(&it);
                tk.extend_from_slice(&iv);
                tk.extend_from_slice(h);
                feed_time.insert(tk.as_slice(), r.hash.as_str())?;

                let mut ck = Vec::with_capacity(r.channel.len() + 9 + h.len());
                ck.extend_from_slice(r.channel.as_bytes());
                ck.push(0);
                ck.extend_from_slice(&iv);
                ck.extend_from_slice(h);
                chan.insert(ck.as_slice(), r.hash.as_str())?;

                for a in &r.accounts {
                    let mut ak = Vec::with_capacity(a.len() + 9 + h.len());
                    ak.extend_from_slice(a.as_bytes());
                    ak.push(0);
                    ak.extend_from_slice(&iv);
                    ak.extend_from_slice(h);
                    acct.insert(ak.as_slice(), r.hash.as_str())?;
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
                let h = rec.hash.as_bytes();
                let mut tk = Vec::with_capacity(16 + h.len());
                tk.extend_from_slice(&inv(rec.timestamp));
                tk.extend_from_slice(&inv(rec.block_id));
                tk.extend_from_slice(h);
                ti.insert(tk.as_slice(), rec.hash.as_str())?;
            }
        }
        w.commit()?;
        Ok(())
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

    /// One transaction by hash.
    pub fn get_tx(&self, hash: &str) -> Result<Option<TxRecord>> {
        let r = self.db.begin_read()?;
        let t = match r.open_table(TXS) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        match t.get(hash)? {
            Some(g) => Ok(Some(de(g.value())?)),
            None => Ok(None),
        }
    }

    fn matches(rec: &TxRecord, o: &FeedOpts) -> bool {
        if let Some(k) = o.kind {
            if rec.kind != k {
                return false;
            }
        }
        if let Some(types) = o.types {
            if !types.iter().any(|x| x == rec_type(rec)) {
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
            let cursor = o.after.map(|(_, bid, h)| {
                let mut k = ch.as_bytes().to_vec();
                k.push(0);
                k.extend_from_slice(&inv(bid));
                k.extend_from_slice(h.as_bytes());
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
            let cursor = o.after.map(|(ts, bid, h)| {
                let mut k = inv(ts).to_vec();
                k.extend_from_slice(&inv(bid));
                k.extend_from_slice(h.as_bytes());
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
                    updates.push((t.hash.clone(), sub));
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
            for (hash, sub) in updates {
                let cur: Option<TxRecord> = match t.get(hash.as_str())? {
                    Some(g) => Some(de(g.value())?),
                    None => None,
                };
                if let Some(mut rec) = cur {
                    if rec.subtype != sub {
                        rec.subtype = sub.to_string();
                        let body = ser(&rec)?;
                        t.insert(hash.as_str(), body.as_slice())?;
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
        after: Option<(u64, &str)>,
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
        let cursor = after.map(|(bid, h)| {
            let mut k = id.as_bytes().to_vec();
            k.push(0);
            k.extend_from_slice(&inv(bid));
            k.extend_from_slice(h.as_bytes());
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
                if !ts.iter().any(|x| x == rec_type(rec)) {
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

    /// Transactions whose program matches `label` within a channel (newest-first),
    /// plus the total count of matches. Walks the per-channel index (capped).
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
        let idx = match r.open_table(IDX_CHANNEL) {
            Ok(t) => t,
            Err(_) => return Ok((vec![], 0)),
        };
        let mut lo = channel.as_bytes().to_vec();
        lo.push(0);
        let mut hi = channel.as_bytes().to_vec();
        hi.push(1);
        let mut out = Vec::new();
        let mut total = 0usize;
        let mut scanned = 0usize;
        for item in idx.range(lo.as_slice()..hi.as_slice())? {
            if scanned >= SCAN_CAP {
                break;
            }
            scanned += 1;
            let (_k, v) = item?;
            if let Some(g) = txs.get(v.value())? {
                let rec: TxRecord = de(g.value())?;
                if rec.program.as_deref() == Some(label) {
                    total += 1;
                    if out.len() < limit {
                        out.push(rec);
                    }
                }
            }
        }
        Ok((out, total))
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
            block_id: blk,
            channel: ch.into(),
            channel_short: "ch".into(),
            slot: Some(blk * 10),
            timestamp: 1_700_000_000_000,
            seen_unix: 0,
        }
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
        assert_eq!(db.get_tx("s1").unwrap().unwrap().subtype, "shield"); // first op = deposit
        assert_eq!(db.get_tx("d1").unwrap().unwrap().subtype, "deshield"); // balance rose
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
        assert_eq!(db.get_tx("v1").unwrap().unwrap().subtype, "deshield");
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
        let got = db.get_tx("bb").unwrap().unwrap();
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
        let pg = db.feed(&FeedOpts { after: Some((1_700_000_000_000, 6, "bb")), limit: 10, ..Default::default() }).unwrap();
        assert_eq!(pg.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["aa"]);

        // oldest-first global + channel feeds are reversed (aa block 5 before bb block 6)
        let old = db.feed(&FeedOpts { oldest: true, limit: 10, ..Default::default() }).unwrap();
        assert_eq!(old.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["aa", "bb"]);
        let oldc = db.feed(&FeedOpts { channel: Some("chan1"), oldest: true, limit: 10, ..Default::default() }).unwrap();
        assert_eq!(oldc.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["aa", "bb"]);
        // oldest pagination: page 1 (limit 1) is aa; the next page (after aa) is the newer bb
        let op1 = db.feed(&FeedOpts { oldest: true, limit: 1, ..Default::default() }).unwrap();
        assert_eq!(op1.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>(), ["aa"]);
        let op2 = db.feed(&FeedOpts { oldest: true, after: Some((1_700_000_000_000, 5, "aa")), limit: 10, ..Default::default() }).unwrap();
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
}
