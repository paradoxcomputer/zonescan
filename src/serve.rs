//! `serve` mode: a live web dashboard fed by *streaming* the L1.
//!
//! A background task subscribes to `/cryptarchia/events/blocks/stream` (ndjson),
//! updates the L1 finality boundary on every event, reads each new block inlined
//! in the event (v0.2.0; older nodes are fetched via `/cryptarchia/blocks/:id`),
//! decodes its inscriptions per channel, and pushes a fresh snapshot to connected
//! browsers over SSE. A lighter periodic poll of `/cryptarchia/info` keeps
//! height/lag/sync-mode fresh and detects an unreachable node.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Json, Response,
    },
    routing::{get, post},
    Router,
};
use futures::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::{
    build_client, channel_alias, channel_tip, collect_inscriptions, decode_inscription,
    decode_inscription_with, find_u64, get_json, info_l1_version, info_mode, info_u64, jget_u64,
    jhex, resolve_channel, scan_channels, short, Decoded, EndpointResult, ScanRec, TxMix,
    MAX_PLAUSIBLE_BLOCK_ID,
};

mod classify;
mod db;
use db::Db;

/// Cap on the rolling transaction feed kept in memory.
const TX_CAP: usize = 4000;
/// Default finalized-slot window for discovery seeding.
const DEFAULT_DISCOVER: u64 = 6000;

// --- runtime configuration (editable via /admin, persisted to disk) --------

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SeqCfg {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub channel_id: String,
    #[serde(default)]
    pub rpc_url: String,
    /// Deep-walk this channel's history to genesis (when `full_history` is on). If no
    /// sequencer sets this, `full_history` deep-walks them all (back-compat); set it
    /// on the channels you actually want the full history for to scope the walk.
    #[serde(default)]
    pub full: bool,
    /// Added automatically by rc4-compatibility discovery (vs. hand-configured), so the
    /// discovery cap counts only auto-added ones.
    #[serde(default, skip_serializing_if = "is_false")]
    pub discovered: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A user-assigned name for a program id - used to label **custom/deployed**
/// programs, which the sequencer's `getProgramIds` registry (the 5 built-ins) can
/// never name. Takes precedence over the registry, so it can also override a built-in.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ProgName {
    /// 64-hex program id (the image id / `program_owner`), with or without `0x`.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
}

/// A deployer-supplied instruction schema (an ABI/IDL) for a custom program, so its
/// risc0-serialized instruction words decode into typed fields. `instruction` is a type
/// descriptor: a primitive name ("u32"/"u64"/"u128"/"bool"/"string"/"bytes"), or an
/// object {"vec":T} / {"struct":[{name,type}]} / {"enum":[{name,fields:[{name,type}]}]}.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ProgSchema {
    /// 64-hex program id this schema decodes.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub instruction: serde_json::Value,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub l1_node_url: String,
    #[serde(default)]
    pub socks5: Option<String>,
    #[serde(default)]
    pub discover_slots: Option<u64>,
    /// When true, walk every configured channel's settled history all the way back
    /// to genesis (block_id 0) and persist it, instead of only the `discover_slots`
    /// window. The forward live stream keeps it current regardless.
    #[serde(default)]
    pub full_history: bool,
    /// Don't store/index clock-program txs (the clock ticks every block - ~99% of all
    /// txs). Liveness (channel tip) and chain consistency are computed at decode, so they
    /// are unaffected; only the per-clock-tx rows are dropped. Cuts the store ~99%.
    #[serde(default, skip_serializing_if = "is_false")]
    pub skip_clock: bool,
    #[serde(default)]
    pub sequencers: Vec<SeqCfg>,
    /// User-assigned names for custom/deployed program ids (id hex -> name).
    #[serde(default)]
    pub program_names: Vec<ProgName>,
    /// Deployer-supplied instruction schemas (ABIs) for custom programs, so their
    /// instruction words decode into typed fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub program_schemas: Vec<ProgSchema>,
    /// When set, auto-discover rc4-compatible sequencers on the L1 and track up to this
    /// many of them (counting only auto-discovered ones, not hand-configured).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discover_limit: Option<usize>,
}

impl Config {
    fn is_configured(&self) -> bool {
        !self.l1_node_url.trim().is_empty() || self.sequencer_mode()
    }
    /// No-L1 mode: no L1 node configured, but at least one sequencer carries both a
    /// channel id and an `rpc_url` we can read blocks from directly (getBlock).
    fn sequencer_mode(&self) -> bool {
        self.l1_node_url.trim().is_empty()
            && self
                .sequencers
                .iter()
                .any(|s| !s.channel_id.trim().is_empty() && !s.rpc_url.trim().is_empty())
    }
    fn base(&self) -> String {
        self.l1_node_url.trim().trim_end_matches('/').to_string()
    }
    fn socks(&self) -> Option<String> {
        self.socks5.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from)
    }
    /// Resolved (alias->hex) channel ids from the configured sequencers.
    fn channel_ids(&self) -> Vec<String> {
        self.sequencers
            .iter()
            .filter_map(|s| {
                let c = s.channel_id.trim();
                (!c.is_empty()).then(|| resolve_channel(c).ok()).flatten()
            })
            .collect()
    }
}

/// A trimmed, non-empty environment variable, or None.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Parse a boolean-ish env var (1/true/yes/on => true, else false), or None if unset.
fn env_bool(key: &str) -> Option<bool> {
    env_nonempty(key).map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

/// The data directory holding `config.json`, `store.redb` and `setup-token`.
/// Resolution (matches the npm launcher): `$ZONE_SCAN_DATA`, else
/// `$XDG_CONFIG_HOME/zone-scan`, else `$HOME/.config/zone-scan` (Windows
/// `%APPDATA%/zone-scan`), else `./zone-scan-data` with a warning.
pub fn default_data_dir() -> PathBuf {
    if let Some(d) = env_nonempty("ZONE_SCAN_DATA") {
        return PathBuf::from(d);
    }
    if let Some(x) = env_nonempty("XDG_CONFIG_HOME") {
        return PathBuf::from(x).join("zone-scan");
    }
    if let Some(h) = env_nonempty("HOME") {
        return PathBuf::from(h).join(".config/zone-scan");
    }
    if let Some(a) = env_nonempty("APPDATA") {
        return PathBuf::from(a).join("zone-scan");
    }
    eprintln!("zone-scan: no HOME/ZONE_SCAN_DATA/XDG_CONFIG_HOME set - using ./zone-scan-data for config + store");
    PathBuf::from("zone-scan-data")
}

/// The config-file path: `$ZONE_SCAN_CONFIG`, else `<data dir>/config.json`.
pub fn default_config_path() -> PathBuf {
    if let Some(c) = env_nonempty("ZONE_SCAN_CONFIG") {
        return PathBuf::from(c);
    }
    default_data_dir().join("config.json")
}

/// Parse `ZONE_SCAN_SEQUENCERS` - comma-separated `channel|rpc_url|label|full`
/// entries (only `channel` required; `rpc_url` enables the no-L1 sequencer source;
/// a trailing `full`/`true`/`1` deep-walks that channel's history).
fn parse_sequencers_env(s: &str) -> Vec<SeqCfg> {
    s.split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|e| {
            let mut p = e.split('|').map(str::trim);
            let channel_id = p.next().unwrap_or("").to_string();
            let rpc_url = p.next().unwrap_or("").to_string();
            let label = p.next().unwrap_or("").to_string();
            let full = matches!(p.next(), Some("full") | Some("true") | Some("1"));
            SeqCfg { label, channel_id, rpc_url, full, discovered: false }
        })
        .filter(|s| !s.channel_id.is_empty())
        .collect()
}

/// Overlay `ZONE_SCAN_*` environment variables onto a Config (env wins), so the
/// whole tool can be configured headlessly from an env file with no setup page.
pub fn overlay_env(cfg: &mut Config) {
    if let Some(v) = env_nonempty("ZONE_SCAN_L1_NODE_URL") {
        cfg.l1_node_url = v;
    }
    if let Some(v) = env_nonempty("ZONE_SCAN_SOCKS5") {
        cfg.socks5 = Some(v);
    }
    if let Some(v) = env_bool("ZONE_SCAN_FULL_HISTORY") {
        cfg.full_history = v;
    }
    if let Some(v) = env_bool("ZONE_SCAN_SKIP_CLOCK") {
        cfg.skip_clock = v;
    }
    if let Some(v) = env_nonempty("ZONE_SCAN_DISCOVER_SLOTS").and_then(|s| s.parse::<u64>().ok()) {
        cfg.discover_slots = Some(v);
    }
    if let Some(v) = env_nonempty("ZONE_SCAN_DISCOVER_LIMIT").and_then(|s| s.parse::<usize>().ok()) {
        cfg.discover_limit = Some(v);
    }
    if let Some(v) = env_nonempty("ZONE_SCAN_SEQUENCERS") {
        let seqs = parse_sequencers_env(&v);
        if !seqs.is_empty() {
            cfg.sequencers = seqs;
        }
    }
}

fn load_config(path: &PathBuf) -> Option<Config> {
    let text = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&text) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            eprintln!("zone-scan: ignoring malformed config at {} ({e})", path.display());
            None
        }
    }
}

fn save_config(path: &PathBuf, cfg: &Config) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(cfg)?)?;
    Ok(())
}

// --- setup token (gates configuration changes) -----------------------------

/// 32 hex chars of randomness for the setup token. Reads the OS CSPRNG via
/// `/dev/urandom` where available, falling back to a time/pid/address SplitMix64 mix.
fn random_token() -> String {
    use std::io::Read;
    let mut b = [0u8; 16];
    let from_os = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok();
    if !from_os {
        eprintln!(
            "zone-scan: warning: OS RNG (/dev/urandom) unavailable - the setup token uses a weaker \
             fallback. Set ZONE_SCAN_ADMIN_TOKEN to a strong value of your own."
        );
        let seed = {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let pid = std::process::id() as u64;
            let addr = &b as *const _ as u64;
            t ^ pid.rotate_left(17) ^ addr.rotate_left(33)
        };
        let mut x = seed;
        for chunk in b.chunks_mut(8) {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            for (d, s) in chunk.iter_mut().zip(z.to_le_bytes().iter()) {
                *d = *s;
            }
        }
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The token gating configuration changes. `ZONE_SCAN_ADMIN_TOKEN` if set (a stable,
/// operator-chosen token - an explicit empty value disables gating); else the
/// persisted `<data>/setup-token`; else a fresh random token written there (0600).
fn resolve_admin_token(data_dir: &std::path::Path) -> String {
    if let Ok(t) = std::env::var("ZONE_SCAN_ADMIN_TOKEN") {
        // explicit (possibly empty -> ungated) operator choice
        return t.trim().to_string();
    }
    let path = data_dir.join("setup-token");
    if let Some(t) = std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return t;
    }
    let token = random_token();
    let _ = std::fs::create_dir_all(data_dir);
    if !write_secret_file(&path, token.as_bytes()) {
        eprintln!(
            "zone-scan: warning: could not persist the setup token to {} - it will change on restart \
             (set ZONE_SCAN_ADMIN_TOKEN for a stable token)",
            path.display()
        );
    }
    token
}

/// Write a secret file created `0600` from the start on Unix (no brief
/// world-readable window between create and chmod). Returns whether it wrote.
fn write_secret_file(path: &std::path::Path, data: &[u8]) -> bool {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
        {
            Ok(mut f) => f.write_all(data).is_ok(),
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).is_ok()
    }
}

/// Routes whose effect mutates config/store or spawns expensive work - gated by
/// the setup token. Everything else (the read-only dashboard + API) stays open.
fn is_protected(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    // The /admin (+ /setup) config page is reachable ONLY with the one-time token
    // (printed by `zonescan setup`); the dashboard links nowhere to it.
    // /api/schemas/submit is intentionally NOT gated: it's a dashboard feature that
    // only stores a schema if it decodes real on-chain samples exactly (display-only).
    matches!(
        (method, path),
        (&Method::GET, "/admin")
            | (&Method::GET, "/setup")
            | (&Method::POST, "/api/config")
            | (&Method::GET, "/api/discover")
            | (&Method::GET, "/api/rescan")
            | (&Method::GET, "/api/relabel")
    )
}

/// Constant-time string equality - avoids leaking how many leading characters of
/// the token matched via response timing.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Does the request carry the admin token? Accepts `X-Setup-Token: <t>`,
/// `Authorization: Bearer <t>`, or a `?token=<t>` query parameter.
fn request_token_ok(want: &str, req: &axum::extract::Request) -> bool {
    if want.is_empty() {
        return true; // gating disabled
    }
    let h = req.headers();
    if let Some(v) = h.get("x-setup-token").and_then(|v| v.to_str().ok()) {
        if ct_eq(v.trim(), want) {
            return true;
        }
    }
    if let Some(v) = h.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(t) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")) {
            if ct_eq(t.trim(), want) {
                return true;
            }
        }
    }
    if let Some(q) = req.uri().query() {
        for kv in q.split('&') {
            if let Some(t) = kv.strip_prefix("token=") {
                if ct_eq(t.trim(), want) {
                    return true;
                }
            }
        }
    }
    false
}

/// Middleware: reject unauthenticated requests to the protected (mutating) routes.
async fn auth_layer(
    State(app): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if is_protected(req.method(), req.uri().path()) && !request_token_ok(&app.admin_token, &req) {
        return (
            StatusCode::UNAUTHORIZED,
            "setup token required - pass X-Setup-Token, Authorization: Bearer, or ?token= (see startup log / <data>/setup-token)",
        )
            .into_response();
    }
    next.run(req).await
}

/// A sequencer is "alive" if its latest inscription is within this many L1 slots
/// of the finality frontier (`lib`). This is finality-lag-independent: finalized
/// blocks are always ~the finality window old in wall-clock, so we measure
/// "is it keeping up with the chain" in slots instead. (A streamed tip block sits
/// above `lib`, so it trivially passes.)
const ALIVE_SLOTS: u64 = 400;
/// Primary liveness: a sequencer is alive if its channel `tip` (polled from
/// `/channel/:id` every few seconds) has changed within this many seconds - i.e.
/// it settled a block recently. Independent of the (Tor-flaky) blocks stream.
const ALIVE_TIP_SECS: u64 = 600;

fn now_unix() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

// --- internal mutable tracking state ---------------------------------------

#[derive(Default)]
struct L1Track {
    reachable: bool,
    height: Option<u64>,
    tip_slot: Option<u64>,
    lib_slot: Option<u64>,
    prev_slot: Option<u64>,
    /// wall-clock of the last tip/lib increase; `advancing` is derived from this over a
    /// time window, so it doesn't flicker when consecutive events repeat the same slot.
    last_advance_unix: u64,
    last_event_unix: u64,
    /// v0.2.0 `/cryptarchia/info` sync mode: "online" (synced) / "bootstrapping"
    /// (IBD) / "awaiting"; None on a 0.1.2 node (no `mode` field).
    mode: Option<String>,
    /// L1 REST API version family detected from `/cryptarchia/info` ("0.2.x" nested /
    /// "0.1.x" flat); None until the first successful info poll.
    l1_version: Option<&'static str>,
    /// Consecutive failed info polls; only flips `reachable` off after a few, so
    /// a single flaky-Tor timeout doesn't blink the dashboard to "unreachable".
    fail_streak: u32,
}

/// Result of cross-checking a sequencer's settled chain against the L1 (and its
/// RPC). All-zero counts with `checked > 0` means the chain verified clean.
#[derive(Default, Clone, Serialize, Deserialize)]
struct Consistency {
    /// blocks for which we recomputed the hash (decode build only)
    checked: u64,
    /// header hash != recompute of block contents (tampered/invalid)
    hash_failures: u64,
    /// a block's prev_hash didn't match the previous block's hash (forked/broken chain)
    chain_breaks: u64,
    /// non-contiguous block ids (skipped settlement)
    id_gaps: u64,
}

impl Consistency {
    /// True when *every* checked block fails the hash recompute - the signature of a
    /// decode/version skew (the explorer's vendored `common` hashes blocks differently
    /// than this sequencer), not selective tampering. Treated as "recompute n/a".
    fn hash_skew(&self) -> bool {
        self.checked > 0 && self.hash_failures == self.checked
    }
    /// The green/red verdict is driven by **chain linkage** + non-uniform hash
    /// failures - the unambiguous "the sequencer broke/forged its chain" signals.
    /// A uniform hash failure is version skew (surfaced separately), and id gaps are
    /// surfaced separately too (often an explorer-side missed or not-yet-settled tip
    /// block rather than a sequencer fault), so neither alone trips the warning.
    fn ok(&self) -> bool {
        self.chain_breaks == 0 && (self.hash_failures == 0 || self.hash_skew())
    }
}

/// Verify one channel's settled chain, given its blocks in **ascending block_id**
/// order: count hash-recompute failures, broken parent links, and id gaps. Light
/// builds (empty `hash`) yield an all-zero verdict (`checked == 0`, "not verified").
fn verify_chain<'a>(blocks_ascending: impl Iterator<Item = &'a Decoded>) -> Consistency {
    let mut c = Consistency::default();
    let mut prev: Option<&Decoded> = None;
    for d in blocks_ascending {
        if d.hash.is_empty() {
            prev = Some(d);
            continue; // light build: chain not verifiable
        }
        c.checked += 1;
        if !d.hash_ok {
            c.hash_failures += 1;
        }
        if let Some(p) = prev {
            if d.block_id == p.block_id + 1 {
                if !p.hash.is_empty() && d.prev_hash != p.hash {
                    c.chain_breaks += 1;
                }
            } else if d.block_id > p.block_id + 1 {
                c.id_gaps += 1;
            }
        }
        prev = Some(d);
    }
    c
}

#[derive(Default, Clone, Serialize, Deserialize)]
struct SeqTrack {
    latest_block_id: u64,
    /// Highest block id known irreversibly settled on the L1 - either the sequencer marked
    /// it `bedrock_status = Finalized`, or we read its inscription from an L1 block at a slot
    /// at/below the L1's last-irreversible slot (`lib`). A tx is "final" when block_id <= this.
    finalized_block_id: u64,
    /// Highest block id known *inscribed* on the L1 but not necessarily past `lib` yet -
    /// `bedrock_status` Safe/Finalized, or seen in an L1 block above `lib`. Always
    /// `>= finalized_block_id`. A tx in `(finalized_block_id, safe_block_id]` is "on L1,
    /// finalizing"; above it, "pending" (not yet inscribed / not yet observed on L1).
    /// `#[serde(default)]`: added after 46ffac8, so old persisted summaries lack it.
    #[serde(default)]
    safe_block_id: u64,
    first_block_id: u64,
    first_seen_unix: u64,
    last_block_unix: u64,
    inscriptions_seen: u64,
    tx_count_last: u32,
    tx_mix: Option<TxMix>,
    seeded: bool,
    inited: bool,
    /// The channel's balance on the Logos L1 (collateral), from `/channel/:id`.
    l1_balance: Option<String>,
    /// Number of authorized signer keys on the L1 channel.
    l1_signers: usize,
    /// Chain-consistency verdict over the scanned window.
    consistency: Consistency,
    /// The sequencer's self-reported tip (`getLastBlockId` via its RPC), to
    /// cross-check against what it actually settled on L1.
    seq_tip: Option<u64>,
    /// L1 slot of this channel's latest inscription (for frontier-relative liveness).
    latest_slot: u64,
    /// (block_id, hash) of the last block fed to the live per-block verifier, so
    /// the next streamed block can be chain-checked against it.
    verify_cursor: Option<(u64, String)>,
    /// last observed channel `tip` (MsgId hex) + when it last changed - the
    /// stream-independent liveness signal, polled from `/channel/:id`.
    last_tip: String,
    tip_change_unix: u64,
    /// detected LEZ build ("rc3"/"rc4"), from a recognized built-in program id.
    version: Option<String>,
    // --- L1 channel-tip metadata (`/channel/:id`), for the pending-activity panel ---
    /// L1 slot of the channel's settlement tip (`tip_slot`) - the frontier of on-L1
    /// activity, which may sit above `lib` (finalizing, not yet decodable) for L1-only
    /// channels. `#[serde(default)]`: added after 7a83cf4, absent in old summaries.
    #[serde(default)]
    l1_tip_slot: Option<u64>,
    /// The tip sequencer's starting L1 slot (`tip_sequencer_starting_slot`) - the low
    /// bound of the current activity range shown in the pending panel.
    #[serde(default)]
    l1_tip_start_slot: Option<u64>,
    /// Accredited signer keys on the L1 channel (hex), from `accredited_keys`.
    #[serde(default)]
    l1_accredited_keys: Vec<String>,
    /// Signing threshold to inscribe (`configuration_threshold`).
    #[serde(default)]
    l1_config_threshold: Option<u64>,
    /// Threshold to withdraw the channel balance (`withdraw_threshold`).
    #[serde(default)]
    l1_withdraw_threshold: Option<u64>,
    /// True once we've decoded a real *user* transaction (any non-clock tx) for this
    /// channel - so its tx table has content and needs no "activity" explainer panel.
    #[serde(default)]
    user_tx_seen: bool,
    /// True once an inscription didn't decode as an rc5 block (implausible block_id): a raw
    /// text/data inscription, not a sequencer block. Its content IS rendered (as raw-inscription
    /// rows); this flag only drives the channel-level "raw" activity summary.
    #[serde(default)]
    saw_undecodable: bool,
}

impl SeqTrack {
    /// Verify one freshly-decoded block against the running chain state and fold
    /// the result into this channel's consistency verdict. Called per block from
    /// the live stream, so the verdict updates as the sequencer settles.
    fn verify(&mut self, d: &Decoded) {
        if d.hash.is_empty() {
            return; // light build: nothing to verify
        }
        self.consistency.checked += 1;
        if !d.hash_ok {
            self.consistency.hash_failures += 1;
        }
        if let Some((pid, ph)) = self.verify_cursor.clone() {
            if d.block_id == pid + 1 {
                if d.prev_hash != ph {
                    self.consistency.chain_breaks += 1;
                }
            } else if d.block_id > pid + 1 {
                self.consistency.id_gaps += 1;
            }
        }
        if self.verify_cursor.as_ref().map_or(true, |(p, _)| d.block_id >= *p) {
            self.verify_cursor = Some((d.block_id, d.hash.clone()));
        }
    }
}

impl SeqTrack {
    fn observe(&mut self, d: &Decoded, now: u64) {
        self.inscriptions_seen += 1;
        self.last_block_unix = now;
        self.seeded = false;
        // An undecodable (non-rc5) block carries a garbage block_id and no txs: count it,
        // but don't let it corrupt the tip / first / tx fields.
        if d.undecodable {
            return;
        }
        if !self.inited || self.first_seen_unix == 0 {
            self.first_block_id = d.block_id;
            self.first_seen_unix = now;
            self.inited = true;
        }
        self.latest_block_id = self.latest_block_id.max(d.block_id);
        self.first_block_id = self.first_block_id.min(d.block_id);
        self.tx_count_last = d.tx_count;
        if d.tx_mix.is_some() {
            self.tx_mix = d.tx_mix.clone();
        }
    }
}

struct ServerState {
    node: String,
    l1: L1Track,
    seqs: HashMap<String, SeqTrack>,
    txs: VecDeque<TxRecord>,
    seen: HashSet<String>,
    /// account id -> latest on-chain public post-state balance we've observed.
    accounts: HashMap<String, AcctBal>,
    /// true while the initial discovery scan is running (for a "scanning…" UI hint).
    discovering: bool,
}

#[derive(Default, Clone, Serialize, Deserialize)]
struct AcctBal {
    balance: Option<String>,
    block_id: u64,
    ts: u64,
    /// channel (sequencer) this account was last seen in - used to pick the
    /// right sequencer RPC for an exact balance lookup.
    channel: String,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// One transaction in the rolling feed: a decoded tx plus its on-chain context.
#[derive(Clone, Default, Serialize, Deserialize)]
struct TxRecord {
    hash: String,
    /// public | private | deploy | raw (a non-block "raw inscription" - see `raw_payload`).
    kind: String,
    /// privacy-preserving operation subtype: shield / deshield / private-send.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    subtype: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    program: Option<String>,
    accounts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    nullifiers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    commitments: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encrypted_outputs: Option<usize>,
    /// privacy txs: the primary public account's post-balance, used by relabel_privacy()
    /// to resolve shield (balance fell) vs deshield (balance rose) from the delta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub_balance: Option<String>,
    /// raw risc0-serialized instruction words (public txs); decoded per-program in UI
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    instruction_data: Vec<u32>,
    /// ProgramDeployment: the program id (image id) the deployed ELF produces.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    deploy_program: String,
    /// ProgramDeployment: size of the deployed guest ELF (bytes), downloadable at /api/elf/:hash.
    #[serde(default, skip_serializing_if = "is_zero")]
    bytecode_len: usize,
    /// For a "raw" inscription tx (`kind == "raw"`): the raw `payload.inscription` bytes. Kept
    /// so the tx-detail can render the content (UTF-8 text when printable, else a hex dump).
    /// Persisted, but stripped from list rows and re-rendered as `raw_text`/`raw_hex` on the
    /// detail (see `enrich_tx` / `enrich_tx_detail`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    raw_payload: Vec<u8>,
    block_id: u64,
    channel: String,
    channel_short: String,
    slot: Option<u64>,
    timestamp: u64,
    seen_unix: u64,
}

/// Build feed records from a decoded inscription + its context.
fn records_from(channel: &str, slot: Option<u64>, d: &Decoded, seen_unix: u64) -> Vec<TxRecord> {
    // A raw (non-block) inscription doesn't decode to an rc5 sequencer block. Rather than drop
    // it, surface it as ONE "raw" tx keyed by its `mantle_tx.hash` (its on-L1 inscription id),
    // carrying the raw payload bytes so the tx-detail can show the actual content. It has no
    // decodable txs, so we never touch `d.txs` here.
    if d.undecodable {
        if d.raw_tx_hash.is_empty() {
            return vec![]; // no carrying hash to key it by (e.g. a sequencer-RPC block body)
        }
        // A raw inscription has no L2 block timestamp, so give it a real, sortable one: its
        // observation time (seen_unix, else now). Crucially it's stored in the SAME
        // MILLISECOND scale as block timestamps, because the global feed is a recency-ordered
        // window (inv(timestamp)) — a `timestamp: 0` (or a seconds-scale value) would sort
        // below every block and fall off the window, hiding raw txs from the home feed.
        let seen = if seen_unix > 0 { seen_unix } else { now_unix() };
        return vec![TxRecord {
            hash: d.raw_tx_hash.clone(),
            kind: "raw".to_string(),
            channel: channel.to_string(),
            channel_short: short(channel),
            slot,
            timestamp: seen.saturating_mul(1000),
            seen_unix: seen,
            raw_payload: d.raw_payload.clone(),
            ..Default::default()
        }];
    }
    let skip_clock = SKIP_CLOCK.load(Ordering::Relaxed);
    d.txs
        .iter()
        // clock ticks every block (~99% of txs); drop them from storage when configured
        // (consistency/liveness use the decoded block directly, so they're unaffected).
        .filter(|t| !skip_clock || !t.program.as_deref().is_some_and(is_clock_program))
        .map(|t| TxRecord {
            hash: t.hash.clone(),
            kind: t.kind.clone(),
            subtype: t.subtype.clone(),
            program: t.program.clone(),
            accounts: t.accounts.clone(),
            nullifiers: t.nullifiers.clone(),
            commitments: t.commitments.clone(),
            encrypted_outputs: t.encrypted_outputs,
            pub_balance: if t.kind == "private" {
                t.post_states.first().map(|p| p.balance.clone())
            } else {
                None
            },
            instruction_data: t.instruction_data.clone(),
            deploy_program: t.deploy_program.clone(),
            bytecode_len: t.deploy_bytecode.len(),
            raw_payload: Vec::new(), // decodable block txs carry no raw inscription payload
            block_id: d.block_id,
            channel: channel.to_string(),
            channel_short: short(channel),
            slot,
            timestamp: d.timestamp,
            seen_unix,
        })
        .collect()
}

/// Push a tx to the front of the feed (newest first), de-duplicating by hash and
/// trimming to the cap.
fn push_tx(s: &mut ServerState, rec: TxRecord) {
    if rec.hash.is_empty() || !s.seen.insert(rec.hash.clone()) {
        return;
    }
    s.txs.push_front(rec);
    while s.txs.len() > TX_CAP {
        if let Some(old) = s.txs.pop_back() {
            s.seen.remove(&old.hash);
        }
    }
}

/// Ingest one decoded inscription: push its txs to the feed and update the
/// account balance index from any public post-states the txs carry.
fn ingest(s: &mut ServerState, channel: &str, slot: Option<u64>, d: &Decoded, now: u64) {
    for rec in records_from(channel, slot, d, now) {
        push_tx(s, rec);
    }
    for t in &d.txs {
        // record which sequencer each touched account belongs to
        for a in &t.accounts {
            s.accounts.entry(a.clone()).or_default().channel = channel.to_string();
        }
        // L1-native (post-state) balance as a fallback when no sequencer RPC
        for ps in &t.post_states {
            let e = s.accounts.entry(ps.id.clone()).or_default();
            e.channel = channel.to_string();
            if e.balance.is_none() || d.block_id >= e.block_id {
                e.balance = Some(ps.balance.clone());
                e.block_id = d.block_id;
                e.ts = d.timestamp;
            }
        }
    }
    // Recency: drive ALIVE/IDLE from the block's own L2 production timestamp
    // (so a channel seeded from discovery still shows ALIVE if it's producing).
    let block_unix = if d.timestamp > 1_000_000_000_000 {
        d.timestamp / 1000
    } else {
        d.timestamp
    };
    {
        let e = s.seqs.entry(channel.to_string()).or_default();
        if block_unix > 1_000_000_000 && block_unix > e.last_block_unix {
            e.last_block_unix = block_unix;
        }
        if let Some(sl) = slot {
            e.latest_slot = e.latest_slot.max(sl);
        }
        // Classify the channel's content (drives the activity panel, idempotent):
        // - a non-block (raw) inscription => raw text/data, rendered as its own row.
        // - any non-clock tx => real user activity (the tx table has content).
        if d.undecodable {
            e.saw_undecodable = true;
        }
        if d.txs.iter().any(|t| !t.program.as_deref().is_some_and(is_clock_program)) {
            e.user_tx_seen = true;
        }
        // advance the L1-finality thresholds from the block's own bedrock_status (the
        // sequencer-RPC source). Finalized => beyond lib (irreversible); Safe => inscribed
        // but not yet past lib. Finalized implies Safe, so raise both accordingly. NOTE:
        // the sequencer freezes inscribed blocks at Pending and (rc4/rc5) only transitions
        // its own store Pending->Finalized, so `bedrock_safe` rarely fires from the RPC; the
        // Safe tier is mainly surfaced from the L1 read via `raise_finality` (see call sites).
        if d.bedrock_safe {
            e.safe_block_id = e.safe_block_id.max(d.block_id);
        }
        if d.bedrock_final {
            e.finalized_block_id = e.finalized_block_id.max(d.block_id);
        }
        // tag the sequencer's LEZ build from a recognized program id (clock every block)
        if e.version.is_none() {
            for t in &d.txs {
                if let Some(v) = t.program.as_deref().and_then(lez_version) {
                    e.version = Some(v.to_string());
                    break;
                }
            }
        }
    }
}

/// Raise a channel's L1-finality thresholds for a block observed *inscribed on the L1*.
/// Being in an L1 block means it is at least **Safe** (inscribed), so `safe_block_id` is
/// raised unconditionally; it is additionally **Finalized** (irreversible) once its L1
/// block is past the last-irreversible slot, which the caller passes as `finalized`.
/// This is the primary Safe/Finalized signal in L1 mode, because the sequencer freezes
/// inscribed blocks at `bedrock_status = Pending` (so the decoded status can't tell us).
/// Additive: never lowers a threshold.
fn raise_finality(e: &mut SeqTrack, block_id: u64, finalized: bool) {
    e.safe_block_id = e.safe_block_id.max(block_id);
    if finalized {
        e.finalized_block_id = e.finalized_block_id.max(block_id);
    }
}

/// Whether a channel has recent on-L1 inscriptions we can't decode yet (settled but not
/// finalized, and the node serves no queryable copy until finality) - the pending-activity
/// signal. Only for L1-only channels (`seq_tip` None => no sequencer RPC): an RPC-indexed
/// channel like 8888 shows every block (as "on L1 · finalizing"), so nothing is hidden.
/// True when its L1 settlement tip is above finality (`tip_slot > lib_slot`), or it has an
/// active tip (`tip_slot > start_slot`) but we've indexed nothing.
fn has_pending_activity(t: &SeqTrack, lib_slot: Option<u64>) -> bool {
    t.seq_tip.is_none()
        && t.l1_tip_slot.is_some_and(|tip| {
            let above_lib = lib_slot.is_some_and(|lib| tip > lib);
            let unindexed_but_active =
                t.inscriptions_seen == 0 && t.l1_tip_start_slot.is_some_and(|st| tip > st);
            above_lib || unindexed_but_active
        })
}

/// Classify a channel that has detected activity but renders no user-tx rows, so the zone
/// page can show an HONEST explainer instead of a blank/misleading page. Three cases:
/// - `"finalizing"`: recent inscriptions above finality (`tip_slot > lib`) we can't read
///   yet - could be clock heartbeats OR user txs, unknown until final. Neutral wording.
/// - `"raw"`: finalized inscriptions that aren't sequencer blocks but raw text/data
///   inscriptions. Their content IS shown (each is now a raw-inscription tx row with its own
///   detail page); the panel is just a summary pointing at those rows.
/// - `"clock-only"`: finalized inscriptions that decode cleanly but carry only the clock
///   heartbeat (no user tx) - an idle channel, not a decode failure.
/// Returns `None` when the channel renders user txs (table has content) or has nothing.
fn activity_state(t: &SeqTrack, lib_slot: Option<u64>) -> Option<&'static str> {
    if has_pending_activity(t, lib_slot) {
        return Some("finalizing");
    }
    // Finalized: only explain channels that render no user-tx rows.
    if t.user_tx_seen {
        return None;
    }
    if t.saw_undecodable {
        // not a sequencer block but a raw text/data inscription - its content is now rendered
        // as raw-inscription rows; this panel is only a summary of them.
        return Some("raw");
    }
    if t.inscriptions_seen > 0 {
        return Some("clock-only"); // decoded fine, but every tx was a clock heartbeat
    }
    None
}

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<ServerState>>,
    tx: broadcast::Sender<String>,
    config: Arc<Mutex<Config>>,
    config_path: Arc<PathBuf>,
    /// Bumped on every config apply; scan tasks exit when their captured value
    /// no longer matches, so a re-config cleanly supersedes the old scan.
    generation: Arc<AtomicU64>,
    /// HTTP client (with the configured SOCKS proxy) for sequencer-RPC calls.
    client: Arc<Mutex<Option<Client>>>,
    /// Durable store for decoded block/tx data (redb); None if it failed to open.
    db: Option<Arc<Db>>,
    /// program-id hex -> human name, from each sequencer's `getProgramIds` registry.
    programs: Arc<Mutex<HashMap<String, String>>>,
    /// program-id hex -> best-guess name (fingerprint classifier), for ids NOT in any name
    /// map. Refreshed periodically from the store; rendered as `≈ name` (unverified).
    guesses: Arc<Mutex<HashMap<String, classify::Guess>>>,
    /// cache of resolved token info, keyed by account id (holding or definition).
    token_cache: Arc<Mutex<HashMap<String, Value>>>,
    /// Token gating configuration changes (see `resolve_admin_token`); empty = open.
    admin_token: Arc<String>,
}

// --- snapshot (the JSON the browser sees) ----------------------------------

#[derive(Serialize)]
struct Snapshot {
    node: String,
    updated_unix: u64,
    decode_feature: bool,
    discovering: bool,
    /// clock txs aren't stored (the feed shows only non-clock txs).
    skip_clock: bool,
    tx_total: usize,
    l1: L1Snap,
    sequencers: Vec<SeqSnap>,
}

#[derive(Serialize)]
struct L1Snap {
    reachable: bool,
    height: Option<u64>,
    tip_slot: Option<u64>,
    lib_slot: Option<u64>,
    finality_lag: Option<u64>,
    advancing: Option<bool>,
    last_event_unix: u64,
    /// v0.2.0 sync mode ("online"/"bootstrapping"/"awaiting"); None on 0.1.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    /// True when the node reports fully synced (`mode == "online"`); None when the
    /// node doesn't expose a mode (0.1.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    synced: Option<bool>,
    /// L1 REST API version family ("0.2.x"/"0.1.x") for the header version tag; None
    /// until the first successful `/cryptarchia/info` poll.
    #[serde(skip_serializing_if = "Option::is_none")]
    l1_version: Option<&'static str>,
}

#[derive(Serialize)]
struct SeqSnap {
    channel: String,
    channel_short: String,
    latest_block_id: u64,
    /// highest L1-finalized block id (see SeqTrack); the client tags a tx "final" if its
    /// block_id <= this. 0 = unknown (light build / no finality info yet).
    finalized_block_id: u64,
    /// highest L1-inscribed ("Safe") block id (see SeqTrack); a tx with
    /// finalized_block_id < block_id <= this tags "on L1 · finalizing". Always >= finalized.
    safe_block_id: u64,
    inscriptions_seen: u64,
    tx_count_last: u32,
    tx_mix: Option<TxMix>,
    last_block_unix: u64,
    blocks_per_min: Option<f64>,
    alive: bool,
    seeded: bool,
    l1_balance: Option<String>,
    l1_signers: usize,
    consistency: Consistency,
    /// None = not verified (no decode / no blocks); Some(true/false) = chain verdict.
    consistent: Option<bool>,
    /// sequencer's self-reported tip (getLastBlockId) for the L1 cross-check.
    seq_tip: Option<u64>,
    /// unix secs when the channel tip last changed (it settled a block); 0 if unseen.
    tip_change_unix: u64,
    /// detected LEZ build ("rc3"/"rc4"), or None if not yet recognized.
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    // --- L1 channel-tip metadata + pending-activity flag (`/channel/:id`) ---
    /// L1 slot of the channel's settlement tip.
    #[serde(skip_serializing_if = "Option::is_none")]
    l1_tip_slot: Option<u64>,
    /// The tip sequencer's starting L1 slot (low bound of the current activity range).
    #[serde(skip_serializing_if = "Option::is_none")]
    l1_tip_start_slot: Option<u64>,
    /// Channel settlement tip hash (`tip_message`), hex.
    #[serde(skip_serializing_if = "String::is_empty")]
    tip_message: String,
    /// Accredited signer keys (hex) that may inscribe to this channel.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    accredited_keys: Vec<String>,
    /// Signing threshold to inscribe.
    #[serde(skip_serializing_if = "Option::is_none")]
    config_threshold: Option<u64>,
    /// Threshold to withdraw the channel balance.
    #[serde(skip_serializing_if = "Option::is_none")]
    withdraw_threshold: Option<u64>,
    /// Honest explainer state when the channel shows no user-tx rows despite activity:
    /// "finalizing" (recent, above finality), "raw" (non-block raw inscriptions, now shown as
    /// their own rows), or "clock-only" (idle heartbeats). None => normal (user txs render).
    #[serde(skip_serializing_if = "Option::is_none")]
    activity_state: Option<&'static str>,
}

fn build_snapshot(s: &ServerState, db_total: Option<u64>) -> Snapshot {
    let now = now_unix();
    let mut sequencers: Vec<SeqSnap> = s
        .seqs
        .iter()
        .map(|(ch, t)| {
            let blocks_per_min = (t.first_seen_unix > 0
                && t.last_block_unix > t.first_seen_unix
                && t.latest_block_id > t.first_block_id)
                .then(|| {
                    let mins = (t.last_block_unix - t.first_seen_unix) as f64 / 60.0;
                    (t.latest_block_id - t.first_block_id) as f64 / mins
                })
                .filter(|v| v.is_finite());
            let alive = if t.tip_change_unix > 0 {
                // primary: did its channel tip move recently (it settled a block)?
                now.saturating_sub(t.tip_change_unix) < ALIVE_TIP_SECS
            } else {
                // fallback before the first /channel poll: frontier-relative
                match s.l1.lib_slot {
                    Some(lib) if t.latest_slot > 0 => lib.saturating_sub(t.latest_slot) < ALIVE_SLOTS,
                    _ => false,
                }
            };
            let activity_state = activity_state(t, s.l1.lib_slot);
            // Never surface a garbage block_id from a mis-parsed non-rc5 body (belt-and-
            // suspenders for any value restored from the durable store): show 0 ("—").
            let latest_block_id = if t.latest_block_id >= MAX_PLAUSIBLE_BLOCK_ID {
                0
            } else {
                t.latest_block_id
            };
            SeqSnap {
                channel: ch.clone(),
                channel_short: short(ch),
                latest_block_id,
                finalized_block_id: t.finalized_block_id,
                // guarantee safe >= finalized for the client thresholds, even if a source
                // raised finalized without a matching safe (shouldn't happen, but cheap).
                safe_block_id: t.safe_block_id.max(t.finalized_block_id),
                inscriptions_seen: t.inscriptions_seen,
                tx_count_last: t.tx_count_last,
                tx_mix: t.tx_mix.clone(),
                last_block_unix: t.last_block_unix,
                blocks_per_min,
                alive,
                seeded: t.seeded,
                l1_balance: t.l1_balance.clone(),
                l1_signers: t.l1_signers,
                consistency: t.consistency.clone(),
                consistent: (t.consistency.checked > 0).then(|| t.consistency.ok()),
                seq_tip: t.seq_tip,
                tip_change_unix: t.tip_change_unix,
                version: t.version.clone(),
                l1_tip_slot: t.l1_tip_slot,
                l1_tip_start_slot: t.l1_tip_start_slot,
                tip_message: t.last_tip.clone(),
                accredited_keys: t.l1_accredited_keys.clone(),
                config_threshold: t.l1_config_threshold,
                withdraw_threshold: t.l1_withdraw_threshold,
                activity_state,
            }
        })
        .collect();
    sequencers.sort_by(|a, b| {
        b.alive
            .cmp(&a.alive)
            .then(b.latest_block_id.cmp(&a.latest_block_id))
    });

    let finality_lag = match (s.l1.tip_slot, s.l1.lib_slot) {
        (Some(t), Some(l)) => Some(t.saturating_sub(l)),
        _ => None,
    };
    Snapshot {
        node: s.node.clone(),
        updated_unix: now,
        decode_feature: cfg!(feature = "decode"),
        discovering: s.discovering,
        skip_clock: SKIP_CLOCK.load(Ordering::Relaxed),
        tx_total: db_total.map(|n| n as usize).unwrap_or_else(|| s.txs.len()),
        l1: L1Snap {
            reachable: s.l1.reachable,
            height: s.l1.height,
            tip_slot: s.l1.tip_slot,
            lib_slot: s.l1.lib_slot,
            finality_lag,
            // advancing = the L1 frontier moved within the last 2 minutes
            advancing: Some(s.l1.reachable && now.saturating_sub(s.l1.last_advance_unix) <= 120),
            last_event_unix: s.l1.last_event_unix,
            mode: s.l1.mode.clone(),
            synced: s.l1.mode.as_deref().map(|m| m == "online"),
            l1_version: s.l1.l1_version,
        },
        sequencers,
    }
}

fn broadcast(app: &AppState) {
    let db_total = app.db.as_ref().map(|d| d.tx_total());
    let snap = {
        let s = app.inner.lock().unwrap();
        build_snapshot(&s, db_total)
    };
    // tagged so the client can distinguish snapshots from pushed tx batches.
    if let Ok(d) = serde_json::to_value(&snap) {
        let _ = app.tx.send(json!({"t": "snap", "d": d}).to_string());
    }
}

/// Push a batch of freshly-ingested txs to connected clients (so the feed updates
/// naturally - new rows slide in at the top - instead of polling/reloading).
fn broadcast_txs(app: &AppState, recs: &[TxRecord]) {
    if recs.is_empty() {
        return;
    }
    // enrich with token name+amount so a live-pushed row shows "GOLD 250" like a fetched one
    let enriched: Vec<Value> = recs.iter().map(|r| enrich_tx(app, r)).collect();
    let _ = app.tx.send(json!({"t": "txs", "d": enriched}).to_string());
}

// --- entrypoint ------------------------------------------------------------

/// Slots per `/cryptarchia/blocks` request during discovery seeding.
const CHUNK_SLOTS: u64 = 800;

pub async fn cmd_serve(
    host: &str,
    port: u16,
    config_path: PathBuf,
    seed: Option<Config>,
) -> Result<()> {
    let from_file = load_config(&config_path);
    // A brand-new install defaults to skipping clock txs: the clock ticks every block
    // (~99% of all txs) and adds nothing to liveness/consistency, so indexing it just
    // floods the store + feed. Existing config files and CLI-seeded configs are left as
    // they are, and ZONE_SCAN_SKIP_CLOCK / the admin toggle still override either way.
    let mut config = from_file.clone().or(seed).unwrap_or_else(|| Config {
        skip_clock: true,
        ..Default::default()
    });
    // Persist a CLI-seeded config so it survives restarts.
    if from_file.is_none() && config.is_configured() {
        if let Err(e) = save_config(&config_path, &config) {
            eprintln!("zone-scan: warning: could not persist seeded config to {}: {e}", config_path.display());
        }
    }
    // Headless: ZONE_SCAN_* env vars override the file/seed (re-applied every start).
    overlay_env(&mut config);

    // The data dir (config's parent) holds config.json, store.redb and setup-token.
    let data_dir = config_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let admin_token = resolve_admin_token(&data_dir);
    let token_display = admin_token.clone();
    let token_path = data_dir.join("setup-token");

    // Durable store lives next to the config (e.g. ~/.config/zone-scan/store.redb).
    let db_path = data_dir.join("store.redb");
    let db = match Db::open(&db_path) {
        Ok(d) => {
            println!("zone-scan  ::  store {}  ({} txs)", db_path.display(), d.tx_total());
            Some(Arc::new(d))
        }
        Err(e) => {
            eprintln!("warning: could not open store at {} ({e}); running without persistence", db_path.display());
            None
        }
    };

    let (tx, _rx) = broadcast::channel::<String>(64);
    let app = AppState {
        inner: Arc::new(Mutex::new(ServerState {
            node: config.base(),
            l1: L1Track::default(),
            seqs: HashMap::new(),
            txs: VecDeque::new(),
            seen: HashSet::new(),
            accounts: HashMap::new(),
            discovering: false,
        })),
        tx,
        config: Arc::new(Mutex::new(config.clone())),
        config_path: Arc::new(config_path),
        generation: Arc::new(AtomicU64::new(0)),
        client: Arc::new(Mutex::new(None)),
        db,
        programs: Arc::new(Mutex::new(HashMap::new())),
        guesses: Arc::new(Mutex::new(HashMap::new())),
        token_cache: Arc::new(Mutex::new(HashMap::new())),
        admin_token: Arc::new(admin_token),
    };

    if config.is_configured() {
        apply_config(&app).await?;
        // Standing discovery: find compatible sequencers on the L1 and track up to the cap.
        // Re-runs on an interval (ZONE_SCAN_DISCOVER_INTERVAL_SECS, default 1800s) so a
        // sequencer that launches AFTER startup is picked up automatically - no restart.
        // discover_compatible only re-seeds when it actually finds a NEW channel, so an
        // empty pass is cheap and causes no scan churn.
        if let Some(cap) = config.discover_limit {
            if cap > 0 {
                let a = app.clone();
                let interval = std::env::var("ZONE_SCAN_DISCOVER_INTERVAL_SECS")
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(1800)
                    .max(60);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await; // let the initial seed settle
                    loop {
                        // L1 discovery needs an L1 node; skip while in no-L1 sequencer mode.
                        if !a.config.lock().unwrap().sequencer_mode() {
                            match discover_compatible(&a, cap).await {
                                Ok(f) if !f.is_empty() => {
                                    println!("discover: now tracking {} new sequencer(s)", f.len());
                                }
                                Ok(_) => {}
                                Err(e) => eprintln!("discover: {e:#}"),
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(interval)).await;
                    }
                });
            }
        }
    }

    // Standing program-fingerprint classification: periodically aggregate stored txs into
    // per-program fingerprints and best-guess a name for ids no registry knows (rendered as
    // `≈ name`, unverified). Cheap + bounded; a no-store / no-tx pass is a no-op.
    if app.db.is_some() {
        let a = app.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(8)).await; // let the initial ingest settle
            loop {
                refresh_guesses(&a).await;
                tokio::time::sleep(Duration::from_secs(120)).await;
            }
        });
    }

    let router = Router::new()
        .route("/", get(index))
        .route("/admin", get(admin_page))
        .route("/setup", get(admin_page))
        .route("/logo.png", get(logo_png))
        .route("/favicon.ico", get(logo_png))
        .route("/api/config", get(api_config_get).post(api_config_post))
        .route("/api/state", get(api_state))
        .route("/api/txs", get(api_txs))
        .route("/api/tx/:hash", get(api_tx))
        .route("/api/account/:id", get(api_account))
        .route("/api/program/:id", get(api_program))
        .route("/api/programs", get(api_programs))
        .route("/api/program_guesses", get(api_program_guesses))
        .route("/api/schemas", get(api_schemas))
        .route("/api/schemas/submit", post(api_schema_submit))
        .route("/api/token_of", get(api_token_of))
        .route("/api/token/:id", get(api_token))
        .route("/api/elf/:hash", get(api_elf))
        .route("/api/rescan", get(api_rescan))
        .route("/api/relabel", get(api_relabel))
        .route("/api/discover", get(api_discover))
        .route("/events", get(sse_handler))
        // SPA deep-links: /zone/:id, /zone/:id/tx/:hash, /zone/:id/wallet/:id, /wallet/:id
        .fallback(index)
        // gate the mutating/expensive routes behind the setup token
        .route_layer(axum::middleware::from_fn_with_state(app.clone(), auth_layer))
        .with_state(app);

    let ip: std::net::IpAddr = host.parse().unwrap_or_else(|_| {
        eprintln!("zone-scan: invalid host {host:?}; binding 127.0.0.1");
        std::net::IpAddr::from([127, 0, 0, 1])
    });
    let addr = SocketAddr::new(ip, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // 0.0.0.0 / :: aren't browsable - show loopback in the printed URL.
    let view_host = if ip.is_unspecified() { "127.0.0.1".to_string() } else { ip.to_string() };
    println!("zone-scan  ->  http://{addr}");
    if token_display.is_empty() {
        println!("setup page :  http://{view_host}:{port}/setup   (configuration is UNGATED - ZONE_SCAN_ADMIN_TOKEN is empty)");
    } else {
        println!("setup page :  http://{view_host}:{port}/setup?token={token_display}");
        println!("              (token saved at {})", token_path.display());
    }
    if !config.is_configured() {
        println!("not configured yet - open the setup page to set an L1 node and/or a sequencer rpc");
    }
    axum::serve(listener, router).await?;
    Ok(())
}

/// (Re)start the scan against the current config. Bumps the generation so any
/// previously-running scan tasks exit, resets state, and spawns fresh tasks.
async fn apply_config(app: &AppState) -> Result<()> {
    let cfg = app.config.lock().unwrap().clone();
    if !cfg.is_configured() {
        return Ok(());
    }
    SKIP_CLOCK.store(cfg.skip_clock, Ordering::Relaxed);
    let base = cfg.base();
    let socks = cfg.socks();
    let channel_ids = cfg.channel_ids();
    let focus: Option<BTreeSet<String>> =
        (!channel_ids.is_empty()).then(|| channel_ids.iter().cloned().collect());
    let discover = cfg.discover_slots.unwrap_or(DEFAULT_DISCOVER);
    // Depth of the one-shot L1 history seed (slots back from lib_slot). Explicitly-
    // configured channels seed their FULL finalized history by default: a sequencer's
    // settled blocks may predate any recent window (it can settle a burst and then go
    // quiet), and the blocks range endpoint only returns finalized blocks up to lib_slot
    // - so a shallow recent window would ingest nothing and the dashboard would show the
    // channel with zero txs. Broad (unfocused) discovery stays bounded to keep it light;
    // an explicit ZONE_SCAN_DISCOVER_SLOTS overrides either way.
    let seed_depth = match cfg.discover_slots {
        Some(d) => d,
        None if focus.is_some() => u64::MAX, // configured channel(s): scan back to genesis
        None => discover,
    };

    let generation = app.generation.fetch_add(1, Ordering::SeqCst) + 1;

    // last-known per-sequencer summaries from the durable store, so the dashboard
    // shows state immediately on restart (while discovery re-scans the window).
    let restored: HashMap<String, SeqTrack> = app
        .db
        .as_ref()
        .and_then(|d| d.restore().ok())
        .map(|(summaries, _cursors)| summaries.into_iter().collect())
        .unwrap_or_default();

    // reset state for the new target
    {
        let mut s = app.inner.lock().unwrap();
        s.node = base.clone();
        s.l1 = L1Track::default();
        s.txs.clear();
        s.seen.clear();
        s.accounts.clear();
        s.seqs.clear();
        s.discovering = true;
        for ch in &channel_ids {
            let mut t = restored.get(ch).cloned().unwrap_or_default();
            t.seeded = true;
            // re-establish the per-block verify cursor after restart (avoid a
            // false chain-break across the downtime gap)
            t.verify_cursor = None;
            s.seqs.insert(ch.clone(), t);
        }
    }
    broadcast(app);

    let client = build_client(socks.as_deref(), Some(Duration::from_secs(60)), None)?;
    *app.client.lock().unwrap() = Some(client.clone());
    println!(
        "scanning {}  (generation {generation}, {} channel filter)",
        if cfg.sequencer_mode() { "sequencer rpc".into() } else { format!("L1 {base}") },
        if focus.is_some() { "with" } else { "no" }
    );

    if cfg.sequencer_mode() {
        // No-L1: read each configured sequencer's blocks directly over its JSON-RPC.
        {
            let mut s = app.inner.lock().unwrap();
            s.discovering = false;
            s.node = "sequencer rpc".to_string();
        }
        let window = discover;
        for sq in &cfg.sequencers {
            let rpc = sq.rpc_url.trim().to_string();
            let chan = sq.channel_id.trim();
            if rpc.is_empty() || chan.is_empty() {
                continue;
            }
            let Ok(channel) = resolve_channel(chan) else { continue };
            let full = sq.full || cfg.full_history;
            let (a, c) = (app.clone(), client.clone());
            tokio::spawn(
                async move { sequencer_loop(c, rpc, channel, full, window, a, generation, false).await },
            );
        }
        broadcast(app);
    } else {
        // L1 mode: finality poll + live block stream + history seed.
        // long-lived stream: no total timeout, but reconnect if it stalls (180s idle).
        let stream_client = build_client(socks.as_deref(), None, Some(Duration::from_secs(180)))?;
        // periodic info poll (height/lag freshness + reachability)
        {
            let (a, c, b) = (app.clone(), client.clone(), base.clone());
            tokio::spawn(async move {
                while a.generation.load(Ordering::SeqCst) == generation {
                    refresh_info(&c, &b, &a).await;
                    refresh_channels(&c, &b, &a).await;
                    broadcast(&a);
                    tokio::time::sleep(Duration::from_secs(8)).await;
                }
            });
        }
        // live blocks stream
        {
            let (a, c, b, f) = (app.clone(), client.clone(), base.clone(), focus.clone());
            tokio::spawn(async move { stream_loop(stream_client, c, b, a, f, generation).await });
        }
        // one-shot seeding: a full-history backfill to genesis, or the bounded discovery
        // window. Either way the live stream keeps ingesting new blocks.
        {
            let (a, c, b, f) = (app.clone(), client.clone(), base.clone(), focus.clone());
            if cfg.full_history {
                tokio::spawn(async move { backfill_seed(&c, &b, &a, f, generation).await });
            } else {
                tokio::spawn(async move { discover_seed(&c, &b, &a, f, seed_depth, generation).await });
            }
        }
        // The finalized L1 inscriptions carry only the sequencer's CHANNEL-settlement layer
        // (clock / validity / genesis) and trail the sequencer by the L1 finality lag. The
        // user's ZONE transactions (auth-transfer, pinata, token, ata) live in the sequencer's
        // zone blocks, so ALSO ingest those directly over its JSON-RPC (getBlock) when an
        // rpc_url is configured - the authoritative tx feed that keeps up with the sequencer.
        // The L1 read above still drives the version tag / sync / lag; db.commit dedupes by tx
        // hash, so a block seen on both sources isn't double-counted.
        for sq in &cfg.sequencers {
            let rpc = sq.rpc_url.trim().to_string();
            let chan = sq.channel_id.trim();
            if rpc.is_empty() || chan.is_empty() {
                continue;
            }
            let Ok(channel) = resolve_channel(chan) else { continue };
            let full = sq.full || cfg.full_history;
            let (a, c) = (app.clone(), client.clone());
            tokio::spawn(async move {
                sequencer_loop(c, rpc, channel, full, discover, a, generation, true).await
            });
        }
    }
    // fetch each sequencer's program-id registry (getProgramIds) for human names
    {
        let (a, c) = (app.clone(), client.clone());
        let rpcs: Vec<String> = cfg
            .sequencers
            .iter()
            .filter_map(|s| {
                let u = s.rpc_url.trim();
                (!u.is_empty()).then(|| u.to_string())
            })
            .collect();
        tokio::spawn(async move {
            let mut merged: HashMap<String, String> = HashMap::new();
            for url in rpcs {
                if a.generation.load(Ordering::SeqCst) != generation {
                    return;
                }
                if let Some(m) = rpc_get_program_ids(&c, &url).await {
                    merged.extend(m);
                }
                // the clock is a built-in `getProgramIds` omits - resolve it from its
                // fixed account's owner (don't override an explicit registry name).
                if let Some(id) = rpc_program_owner(&c, &url, CLOCK_PROGRAM_ACCOUNT).await {
                    merged.entry(id).or_insert_with(|| "clock".to_string());
                }
            }
            // keep the last-known map if every RPC was unreachable (don't blank names)
            if a.generation.load(Ordering::SeqCst) == generation && !merged.is_empty() {
                *a.programs.lock().unwrap() = merged;
                broadcast(&a);
            }
        });
    }
    Ok(())
}

/// Auto-discover rc4-compatible sequencers on the L1: scan a recent window with NO
/// channel filter, and for every channel not already tracked, decode its blocks under
/// our (rc4) build and recompute their header hashes. A channel is "compatible" when it
/// has at least one block with a real header hash and EVERY such block recomputes
/// correctly - i.e. it runs the same block-hashing build we do. Incompatible
/// (different-version) channels fail the recompute (or don't borsh-decode at all) and
/// are skipped. Up to `total_cap` auto-discovered channels are tracked in total; newly
/// found ones are appended to the config (and persisted), then `apply_config` re-seeds
/// so the backfill + live stream pick them up.
async fn discover_compatible(app: &AppState, total_cap: usize) -> Result<Vec<String>> {
    let cfg = app.config.lock().unwrap().clone();
    if !cfg.is_configured() {
        anyhow::bail!("L1 node not configured");
    }
    let already: BTreeSet<String> = cfg.channel_ids().into_iter().collect();
    let existing = cfg.sequencers.iter().filter(|s| s.discovered).count();
    let budget = total_cap.saturating_sub(existing);
    if budget == 0 {
        return Ok(vec![]);
    }
    let base = cfg.base();
    let socks = cfg.socks();
    // scan EVERY L1 block (genesis -> lib), not just the recent window, so no sequencer
    // is ever missed - however old or briefly-active. One sample block per channel keeps
    // it light despite the full range. `discover_slots`, if set, caps the depth.
    let client = build_client(socks.as_deref(), Some(Duration::from_secs(90)), None)?;
    let gen = app.generation.load(Ordering::SeqCst);
    let lib = match get_json(&client, &format!("{base}/cryptarchia/info")).await {
        EndpointResult::Ok(v) => info_u64(&v, "lib_slot").unwrap_or(0),
        _ => anyhow::bail!("cannot reach L1 node"),
    };
    if lib == 0 {
        return Ok(vec![]);
    }
    let floor = cfg.discover_slots.map(|d| lib.saturating_sub(d)).unwrap_or(0);
    let mut by_chan: BTreeMap<String, Vec<Decoded>> = BTreeMap::new();
    let mut hi = lib;
    loop {
        if app.generation.load(Ordering::SeqCst) != gen {
            return Ok(vec![]); // superseded by a newer config
        }
        let from = hi.saturating_sub(CHUNK_SLOTS).max(floor);
        let url = format!("{base}/cryptarchia/blocks?slot_from={from}&slot_to={hi}");
        if let EndpointResult::Ok(Value::Array(blocks)) = get_json(&client, &url).await {
            for b in &blocks {
                let mut ins = Vec::new();
                collect_inscriptions(b, &mut ins);
                for ri in ins {
                    let cid = ri.channel;
                    if already.contains(&cid) || by_chan.contains_key(&cid) {
                        continue; // already tracked, or already sampled this channel
                    }
                    if let Some(d) = decode_inscription(&ri.value) {
                        by_chan.insert(cid, vec![d]);
                    }
                }
            }
        }
        if from <= floor {
            break;
        }
        hi = from - 1;
    }
    let mut found = Vec::new();
    for (ch, blocks) in by_chan {
        if already.contains(&ch) {
            continue;
        }
        // require real decoded blocks (non-empty header hash) and every one recomputes
        let decoded: Vec<&Decoded> = blocks.iter().filter(|d| !d.hash.is_empty()).collect();
        if !decoded.is_empty() && decoded.iter().all(|d| d.hash_ok) {
            found.push(ch);
            if found.len() >= budget {
                break;
            }
        }
    }

    if !found.is_empty() {
        {
            let mut c = app.config.lock().unwrap();
            for ch in &found {
                c.sequencers.push(SeqCfg {
                    label: format!("seq-{}", &ch[..ch.len().min(6)]),
                    channel_id: ch.clone(),
                    rpc_url: String::new(),
                    full: true,
                    discovered: true,
                });
            }
        }
        let snapshot = app.config.lock().unwrap().clone();
        if let Err(e) = save_config(&app.config_path, &snapshot) {
            eprintln!("discover: failed to persist config: {e:#}");
        }
        println!(
            "discover: +{} rc4-compatible sequencer(s): {}",
            found.len(),
            found.iter().map(|c| &c[..c.len().min(8)]).collect::<Vec<_>>().join(", ")
        );
        apply_config(app).await?;
    }
    Ok(found)
}

/// One-shot discovery: scan recent finalized blocks and seed the feed + per-channel
/// state. Guarded by `generation` so a superseded scan never writes stale data.
async fn discover_seed(
    client: &Client,
    base: &str,
    app: &AppState,
    focus: Option<BTreeSet<String>>,
    discover: u64,
    generation: u64,
) {
    let mut attempt = 0;
    let result = loop {
        if app.generation.load(Ordering::SeqCst) != generation {
            return;
        }
        attempt += 1;
        match scan_channels(client, base, focus.as_ref(), discover, CHUNK_SLOTS, false).await {
            Ok((map, recs, _, _)) => break Some((map, recs)),
            Err(e) => {
                eprintln!("discovery attempt {attempt} failed: {e:#}");
                if attempt >= 5 {
                    eprintln!("giving up on discovery; streaming will pick up channels as they settle");
                    break None;
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    };
    // discovery is done (whether or not it found anything)
    {
        app.inner.lock().unwrap().discovering = false;
    }
    if app.generation.load(Ordering::SeqCst) != generation {
        return;
    }
    if let Some((map, mut recs)) = result {
        recs.sort_by_key(|r| (r.slot.unwrap_or(0), r.decoded.block_id));
        // group decoded blocks per channel for chain verification
        let mut by_ch: HashMap<String, Vec<&ScanRec>> = HashMap::new();
        for r in &recs {
            by_ch.entry(r.channel.clone()).or_default().push(r);
        }
        {
            let mut s = app.inner.lock().unwrap();
            for (ch, agg) in map {
                let e = s.seqs.entry(ch).or_insert_with(SeqTrack::default);
                e.latest_block_id = e.latest_block_id.max(agg.latest_block_id);
                e.first_block_id = if e.first_block_id == 0 {
                    agg.min_block_id
                } else {
                    e.first_block_id.min(agg.min_block_id)
                };
                e.inscriptions_seen = e.inscriptions_seen.max(agg.count);
                e.tx_count_last = agg.tx_count;
                if agg.tx_mix.is_some() {
                    e.tx_mix = agg.tx_mix.clone();
                }
                if let Some(ls) = agg.latest_slot {
                    e.latest_slot = e.latest_slot.max(ls);
                }
                e.seeded = true;
                e.inited = true;
            }
            for r in &recs {
                ingest(&mut s, &r.channel, r.slot, &r.decoded, 0);
                // the discovery scan reads the finalized-only blocks endpoint, so every
                // decodable block it returns is irreversibly settled on the L1. Skip
                // undecodable blocks - their garbage block_id would corrupt the threshold.
                if !r.decoded.undecodable {
                    let e = s.seqs.entry(r.channel.clone()).or_default();
                    raise_finality(e, r.decoded.block_id, true);
                }
            }
            // verify each channel's settled chain: hash recompute + parent links + id contiguity
            for (ch, mut list) in by_ch {
                list.sort_by_key(|r| r.decoded.block_id);
                let c = verify_chain(list.iter().map(|r| &r.decoded));
                if let Some(t) = s.seqs.get_mut(&ch) {
                    t.consistency = c;
                }
            }
        }
        broadcast(app);
        eprintln!("discovery complete");

        // persist the discovered window (dedup keeps re-scans idempotent)
        if let Some(db) = app.db.clone() {
            let all_recs: Vec<TxRecord> = recs
                .iter()
                .flat_map(|r| records_from(&r.channel, r.slot, &r.decoded, 0))
                .collect();
            let mut cur: HashMap<String, u64> = HashMap::new();
            for r in &recs {
                if let Some(sl) = r.slot {
                    let e = cur.entry(r.channel.clone()).or_insert(0);
                    *e = (*e).max(sl);
                }
            }
            let (summaries, accts) = {
                let s = app.inner.lock().unwrap();
                (
                    s.seqs.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>(),
                    s.accounts.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>(),
                )
            };
            let cursors: Vec<(String, u64)> = cur.into_iter().collect();
            let n_recs = all_recs.len();
            match tokio::task::spawn_blocking(move || db.commit(&all_recs, &summaries, &cursors, &accts)).await {
                Ok(Ok(n)) => eprintln!("store: discovery persisted {n} new / {n_recs} recs"),
                Ok(Err(e)) => eprintln!("store: discovery commit error: {e:#}"),
                Err(e) => eprintln!("store: discovery join error: {e}"),
            }
        }
    }
}

/// Cap on the in-memory consistency buffer, so an unfocused genesis walk can't OOM.
const VERIF_CAP: usize = 2_000_000;
/// A focused channel that has neither reached genesis nor shown an inscription for
/// this many consecutive chunks is treated as exhausted/absent and dropped from the
/// walk - so a typo'd or not-yet-settled channel (e.g. one that hasn't settled here)
/// can't force a multi-hour walk down to slot 0. Generous (~this×CHUNK_SLOTS slots of
/// continuous silence) and logged when it fires.
const BACKFILL_IDLE_CHUNKS: u32 = 80;

/// Stable per-(node, focus) fingerprint for the backfill resume cursors, so a
/// re-config that changes the node or the tracked channel set doesn't resume against
/// a cursor that was walked for a different scope.
fn scope_fp(base: &str, focus: &Option<BTreeSet<String>>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    base.hash(&mut h);
    match focus {
        None => "*all*".hash(&mut h),
        Some(f) => {
            for c in f {
                c.hash(&mut h); // BTreeSet iterates sorted => order-stable
            }
        }
    }
    h.finish()
}

/// Per-channel accumulators threaded across a backfill's gap-fill and deep walks.
#[derive(Default)]
struct WalkAcc {
    /// channel -> (block_id -> slim Decoded), for the final chain-consistency pass
    verif: HashMap<String, BTreeMap<u64, Decoded>>,
    verif_count: usize,
    /// channel -> lowest block_id seen (drives the genesis early-stop)
    min_id: HashMap<String, u64>,
    /// channel -> consecutive chunks with no inscription (drives the exhaustion stop)
    idle: HashMap<String, u32>,
    /// every channel touched by either walk (for the final consistency/summary update)
    touched: HashSet<String>,
}

/// Fold per-channel chain verdicts computed from a walk's `verif` buffer into live
/// state, **never downgrading** a verdict that already covers at least as many
/// blocks - so a partial/gap-fill pass (or the live stream's accumulated verdict)
/// can't clobber a higher-coverage verdict, while still letting a fuller pass win.
fn merge_consistency(s: &mut ServerState, verif: &HashMap<String, BTreeMap<u64, Decoded>>) {
    for (ch, blocks) in verif {
        let c = verify_chain(blocks.values());
        if let Some(t) = s.seqs.get_mut(ch) {
            if c.checked >= t.consistency.checked {
                t.consistency = c;
            }
        }
    }
}

/// Walk finalized blocks backward through `lo_stop ..= hi_start` in chunks, folding
/// each into live state + the feed and persisting it to the durable store. When
/// `floor_key` is set, the low-water floor is advanced (in the same off-reactor job,
/// *after* the records commit) so a deep walk resumes near where it stopped. With
/// `exhaustion`, stops early once every focused channel is at genesis or silent for
/// `BACKFILL_IDLE_CHUNKS` chunks. Honors `generation` at every iteration and after
/// each await. Returns `false` iff superseded by a re-config (caller must stop); a
/// re-scanned boundary slot is always dedup-safe.
#[allow(clippy::too_many_arguments)]
async fn backfill_walk(
    client: &Client,
    base: &str,
    app: &AppState,
    focus: &Option<BTreeSet<String>>,
    stop_set: &BTreeSet<String>,
    generation: u64,
    hi_start: u64,
    lo_stop: u64,
    exhaustion: bool,
    floor_key: Option<&str>,
    acc: &mut WalkAcc,
) -> bool {
    let chunk = CHUNK_SLOTS.max(1);
    let mut hi = hi_start;
    let mut chunk_n: u64 = 0;
    loop {
        if app.generation.load(Ordering::SeqCst) != generation {
            return false; // superseded
        }
        let from = hi.saturating_sub(chunk).max(lo_stop);
        let url = format!("{base}/cryptarchia/blocks?slot_from={from}&slot_to={hi}");
        let mut decoded: Vec<(String, Option<u64>, Decoded)> = Vec::new();
        if let EndpointResult::Ok(Value::Array(blocks)) = get_json(client, &url).await {
            for b in &blocks {
                let slot = b
                    .get("header")
                    .and_then(|h| jget_u64(h, "slot"))
                    .or_else(|| find_u64(b, "slot"));
                let mut found = Vec::new();
                collect_inscriptions(b, &mut found);
                for ri in found {
                    let cid = ri.channel;
                    if let Some(f) = focus {
                        if !f.contains(&cid) {
                            continue;
                        }
                    }
                    if let Some(d) = decode_inscription_with(&ri.value, ri.tx_hash.as_deref()) {
                        decoded.push((cid, slot, d));
                    }
                }
            }
        }
        if app.generation.load(Ordering::SeqCst) != generation {
            return false; // superseded during the fetch await - don't write stale data
        }

        // Fold this chunk into live state + the feed under a single lock, and gather
        // the records + touched sequencer/account state to persist.
        let mut recs: Vec<TxRecord> = Vec::new();
        let (summaries, accts) = {
            let mut s = app.inner.lock().unwrap();
            for (cid, slot, d) in &decoded {
                ingest(&mut s, cid, *slot, d, 0);
                let e = s.seqs.entry(cid.clone()).or_default();
                // An undecodable (non-rc5) block has a garbage block_id and no txs: don't
                // let it set the tip/first/span/finality fields; `ingest` already flagged
                // `saw_undecodable`, and its L1 slot (below) still marks liveness.
                if !d.undecodable {
                    // `/cryptarchia/blocks` returns only finalized (<= lib) blocks, so every
                    // block seen here is irreversibly settled on the L1.
                    raise_finality(e, d.block_id, true);
                    // descending walk: only the highest id seen sets the "latest" fields
                    let is_new_tip = !e.inited || d.block_id >= e.latest_block_id;
                    if !e.inited {
                        e.first_block_id = d.block_id;
                        e.inited = true;
                    }
                    e.latest_block_id = e.latest_block_id.max(d.block_id);
                    e.first_block_id = e.first_block_id.min(d.block_id);
                    // Idempotent across restarts/re-walks: derive the count from the
                    // contiguous id span rather than incrementing (which would inflate).
                    e.inscriptions_seen = e.latest_block_id.saturating_sub(e.first_block_id) + 1;
                    if is_new_tip {
                        e.tx_count_last = d.tx_count;
                        if d.tx_mix.is_some() {
                            e.tx_mix = d.tx_mix.clone();
                        }
                    }
                }
                if let Some(sl) = slot {
                    e.latest_slot = e.latest_slot.max(*sl);
                }
                e.seeded = true;
                recs.extend(records_from(cid, *slot, d, 0));
            }
            let channels: HashSet<String> = decoded.iter().map(|(c, _, _)| c.clone()).collect();
            let summaries: Vec<(String, SeqTrack)> = channels
                .iter()
                .filter_map(|c| s.seqs.get(c).map(|t| (c.clone(), t.clone())))
                .collect();
            let mut seen = HashSet::new();
            let mut accts: Vec<(String, AcctBal)> = Vec::new();
            for r in &recs {
                for a in &r.accounts {
                    if seen.insert(a.clone()) {
                        if let Some(b) = s.accounts.get(a) {
                            accts.push((a.clone(), b.clone()));
                        }
                    }
                }
            }
            (summaries, accts)
        };

        // Track genesis progress + accumulate the bounded consistency buffer.
        for (cid, _slot, d) in &decoded {
            acc.touched.insert(cid.clone());
            let lo = acc.min_id.entry(cid.clone()).or_insert(u64::MAX);
            *lo = (*lo).min(d.block_id);
            if acc.verif_count < VERIF_CAP {
                let m = acc.verif.entry(cid.clone()).or_default();
                if m
                    .insert(
                        d.block_id,
                        Decoded {
                            block_id: d.block_id,
                            hash: d.hash.clone(),
                            prev_hash: d.prev_hash.clone(),
                            hash_ok: d.hash_ok,
                            ..Default::default()
                        },
                    )
                    .is_none()
                {
                    acc.verif_count += 1;
                }
            }
        }

        // Persist this chunk and (for a deep walk) advance the low-water floor in one
        // off-reactor job. The floor write is a separate txn issued *after* the
        // records commit (via `?`), so a crash between them makes resume re-scan the
        // boundary rather than skip a range; a failed commit never advances the floor.
        if let Some(db) = app.db.clone() {
            let n = recs.len();
            let fk = floor_key.map(str::to_string);
            let elfs = collect_elfs(decoded.iter().map(|(_, _, d)| d));
            let (rc, sm, ac2) = (recs, summaries, accts);
            match tokio::task::spawn_blocking(move || {
                let added = db.commit(&rc, &sm, &[], &ac2)?;
                db.put_elfs(&elfs)?;
                if let Some(fk) = fk {
                    db.set_meta_u64(&fk, from)?;
                }
                anyhow::Ok(added)
            })
            .await
            {
                Ok(Ok(added)) if added > 0 => {
                    eprintln!("backfill: slots {from}..{hi}: +{added} new / {n} recs")
                }
                Ok(Err(e)) => eprintln!("backfill: chunk persist error: {e:#}"),
                Err(e) => eprintln!("backfill: chunk join error: {e}"),
                _ => {}
            }
        }
        if app.generation.load(Ordering::SeqCst) != generation {
            return false; // superseded during the commit await
        }
        broadcast(app);

        // Periodically fold the running chain verdict into live state, so even a long
        // (or never-completing) deep walk shows incremental "verified over N" progress.
        chunk_n += 1;
        if chunk_n % 20 == 0 {
            let mut s = app.inner.lock().unwrap();
            merge_consistency(&mut s, &acc.verif);
        }

        // Stop once every channel in `stop_set` (the full-history targets) is at
        // genesis (block_id 0) or exhausted (silent for BACKFILL_IDLE_CHUNKS chunks).
        if exhaustion && !stop_set.is_empty() {
            let present: HashSet<String> = decoded.iter().map(|(c, _, _)| c.clone()).collect();
            for c in stop_set {
                if present.contains(c) {
                    acc.idle.insert(c.clone(), 0);
                } else {
                    *acc.idle.entry(c.clone()).or_insert(0) += 1;
                }
            }
            let done = stop_set.iter().all(|c| {
                acc.min_id.get(c).copied() == Some(0)
                    || acc.idle.get(c).copied().unwrap_or(0) >= BACKFILL_IDLE_CHUNKS
            });
            if done {
                for c in stop_set {
                    if acc.min_id.get(c).copied() != Some(0) {
                        eprintln!(
                            "backfill: channel {} exhausted at slot {from} - no inscriptions for {BACKFILL_IDLE_CHUNKS} chunks (lowest block_id seen: {:?}); stopping the deep walk",
                            short(c),
                            acc.min_id.get(c)
                        );
                    }
                }
                let mut s = app.inner.lock().unwrap();
                merge_consistency(&mut s, &acc.verif);
                return true;
            }
        }
        if from <= lo_stop {
            let mut s = app.inner.lock().unwrap();
            merge_consistency(&mut s, &acc.verif);
            return true; // reached the lower bound of this walk
        }
        hi = from.saturating_sub(1);
    }
}

/// Full-history backfill: persist each configured channel's **entire settled history**
/// (back to genesis, block_id 0), not just the recent `discover_slots` window. Used
/// instead of `discover_seed` when `full_history` is set; the live stream still
/// ingests new blocks going forward.
///
/// Resumable and restart-safe. Three per-(node,focus) cursors live in the store:
/// `backfill:top` (highest slot covered), `backfill:floor` (deep low-water mark), and
/// `backfill:done` (the downward walk reached genesis/exhaustion). On (re)start it
/// (1) gap-fills any slots finalized since the last run `(top, lib]`, then (2) walks
/// down toward genesis from the floor - unless `done`, in which case the history is
/// already complete and only the gap-fill runs. This makes a completed backfill cheap
/// to restart instead of re-walking the whole chain over Tor every boot.
async fn backfill_seed(
    client: &Client,
    base: &str,
    app: &AppState,
    focus: Option<BTreeSet<String>>,
    generation: u64,
) {
    // Need the finality frontier to know where to start. Retry through Tor flakiness.
    let mut lib_opt: Option<u64> = None;
    for attempt in 1..=10u32 {
        if app.generation.load(Ordering::SeqCst) != generation {
            return;
        }
        if let EndpointResult::Ok(v) = get_json(client, &format!("{base}/cryptarchia/info")).await {
            if let Some(l) = info_u64(&v, "lib_slot") {
                lib_opt = Some(l);
                break;
            }
        }
        if attempt == 10 {
            eprintln!("backfill: could not read lib_slot; the live stream will still ingest new blocks");
            app.inner.lock().unwrap().discovering = false;
            broadcast(app);
            return;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let lib = lib_opt.unwrap();

    let fp = scope_fp(base, &focus);
    let k_floor = format!("backfill:floor:{fp}");
    let k_top = format!("backfill:top:{fp}");
    let k_done = format!("backfill:done:{fp}");

    // Read resume state off the reactor.
    let (resumed_floor, prev_top, prev_done) = match app.db.clone() {
        Some(db) => {
            let (kf, kt, kd) = (k_floor.clone(), k_top.clone(), k_done.clone());
            tokio::task::spawn_blocking(move || {
                (
                    db.get_meta_u64(&kf),
                    db.get_meta_u64(&kt),
                    db.get_meta_u64(&kd) == Some(1),
                )
            })
            .await
            .unwrap_or((None, None, false))
        }
        None => (None, None, false),
    };

    // Channels whose deep history actually gates the walk: the ones flagged `full`
    // in config. If none are flagged, fall back to every focused channel (so a bare
    // `full_history` still deep-walks them all) - set `full` per sequencer to scope.
    let full_set: BTreeSet<String> = {
        let cfg = app.config.lock().unwrap();
        cfg.sequencers
            .iter()
            .filter(|s| s.full)
            .filter_map(|s| resolve_channel(s.channel_id.trim()).ok())
            .collect()
    };
    let stop_set: BTreeSet<String> = if full_set.is_empty() {
        focus.clone().unwrap_or_default()
    } else {
        full_set
    };

    let mut acc = WalkAcc::default();

    // 1) On a resume, re-scan the recent window - from `lib` down to at least
    //    `lib - RECENT_VERIFY_SLOTS`, and no higher than the previous `top`. This
    //    fills slots finalized during downtime (the forward stream only covers
    //    blocks produced while running) AND re-observes recently-active channels
    //    whose blocks were scanned only in a prior run - block-level hashes aren't
    //    persisted, so re-observing them is what lets `merge_consistency` recompute
    //    their chain verdict on restart (e.g. a shallow, recent sequencer).
    //    First run (no prior `top`) skips this: the deep walk below starts at `lib`
    //    and already covers the recent window.
    const RECENT_VERIFY_SLOTS: u64 = 8000;
    if let Some(pt) = prev_top {
        let gap_lo = pt.min(lib.saturating_sub(RECENT_VERIFY_SLOTS));
        if gap_lo < lib {
            eprintln!("backfill: recent re-scan/gap-fill slots {lib}..{gap_lo}");
            if !backfill_walk(client, base, app, &focus, &stop_set, generation, lib, gap_lo, false, None, &mut acc).await {
                return; // superseded
            }
        }
    }
    let new_top = prev_top.map_or(lib, |pt| pt.max(lib));
    if let Some(db) = app.db.clone() {
        let kt = k_top.clone();
        let _ = tokio::task::spawn_blocking(move || db.set_meta_u64(&kt, new_top)).await;
    }

    // 2) Deep walk toward genesis, unless a prior run already completed it.
    if !prev_done {
        let start = match resumed_floor {
            Some(f) if f > 0 && f <= new_top => f,
            _ => new_top,
        };
        eprintln!(
            "backfill: deep walk slots {start}..0 (chunk {CHUNK_SLOTS}){}",
            if resumed_floor.is_some() { " [resumed]" } else { "" }
        );
        if !backfill_walk(client, base, app, &focus, &stop_set, generation, start, 0, true, Some(&k_floor), &mut acc).await {
            return; // superseded - don't mark done, don't run the tail
        }
        if let Some(db) = app.db.clone() {
            let kd = k_done.clone();
            let _ = tokio::task::spawn_blocking(move || db.set_meta_u64(&kd, 1)).await;
        }
    }

    // 3) Tail: fold the final per-channel chain verdict for everything covered this
    //    pass (never downgrading a higher-coverage or stream-accumulated verdict),
    //    clear the "scanning" hint, and persist the summaries.
    if app.generation.load(Ordering::SeqCst) != generation {
        return;
    }
    {
        let mut s = app.inner.lock().unwrap();
        merge_consistency(&mut s, &acc.verif);
        s.discovering = false;
    }
    if let Some(db) = app.db.clone() {
        let summaries: Vec<(String, SeqTrack)> = {
            let s = app.inner.lock().unwrap();
            s.seqs.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        let _ = tokio::task::spawn_blocking(move || db.commit(&[], &summaries, &[], &[])).await;
    }
    // resolve shield vs deshield now that this round's balance history is in the store
    if let Some(db) = app.db.clone() {
        if let Ok(n) = tokio::task::spawn_blocking(move || db.relabel_privacy()).await {
            if let Ok(n) = n {
                if n > 0 {
                    println!("relabel: resolved shield/deshield on {n} privacy tx(s)");
                }
            }
        }
    }
    broadcast(app);
    eprintln!("backfill: round complete");
}

async fn refresh_info(client: &Client, base: &str, app: &AppState) {
    match get_json(client, &format!("{base}/cryptarchia/info")).await {
        EndpointResult::Ok(v) => {
            let now = now_unix();
            let mut s = app.inner.lock().unwrap();
            s.l1.reachable = true;
            s.l1.fail_streak = 0;
            s.l1.height = info_u64(&v, "height");
            if let Some(ts) = info_u64(&v, "slot") {
                if s.l1.tip_slot.is_none_or(|p| ts > p) {
                    s.l1.last_advance_unix = now;
                }
                s.l1.tip_slot = Some(ts);
            }
            if let Some(l) = info_u64(&v, "lib_slot") {
                if s.l1.lib_slot.is_none_or(|p| l > p) {
                    s.l1.last_advance_unix = now;
                }
                s.l1.lib_slot = Some(l);
            }
            s.l1.mode = info_mode(&v);
            s.l1.l1_version = Some(info_l1_version(&v));
            s.l1.last_event_unix = now;
        }
        _ => {
            // Keep last-known values; only declare unreachable after a few misses.
            let mut s = app.inner.lock().unwrap();
            s.l1.fail_streak = s.l1.fail_streak.saturating_add(1);
            if s.l1.fail_streak >= 3 {
                s.l1.reachable = false;
            }
        }
    }
}

/// Refresh each tracked channel's L1 state (collateral balance + signer count)
/// from `GET /channel/:id`, plus the sequencer's self-reported tip (`getLastBlockId`
/// via its RPC) for the L1-vs-sequencer cross-check.
async fn refresh_channels(client: &Client, base: &str, app: &AppState) {
    let channels: Vec<String> = { app.inner.lock().unwrap().seqs.keys().cloned().collect() };
    // resolved channel id -> sequencer RPC url
    let rpc_for: HashMap<String, String> = {
        let cfg = app.config.lock().unwrap();
        cfg.sequencers
            .iter()
            .filter_map(|sc| {
                let u = sc.rpc_url.trim();
                (!u.is_empty())
                    .then(|| resolve_channel(&sc.channel_id).ok().map(|c| (c, u.to_string())))
                    .flatten()
            })
            .collect()
    };
    for ch in channels {
        if let EndpointResult::Ok(v) = get_json(client, &format!("{base}/channel/{ch}")).await {
            let balance = v.get("balance").map(|b| match b {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            });
            // v0.2.0 renamed `keys` -> `accredited_keys` and `tip` -> `tip_message`.
            let keys: Vec<String> = v
                .get("accredited_keys")
                .or_else(|| v.get("keys"))
                .and_then(Value::as_array)
                .map(|a| a.iter().map(jhex).collect())
                .unwrap_or_default();
            let signers = keys.len();
            let tip = channel_tip(&v);
            // channel-tip metadata for the pending-activity panel
            let tip_slot = jget_u64(&v, "tip_slot");
            let tip_start_slot = jget_u64(&v, "tip_sequencer_starting_slot");
            let config_threshold = jget_u64(&v, "configuration_threshold");
            let withdraw_threshold = jget_u64(&v, "withdraw_threshold");
            let now = now_unix();
            let mut s = app.inner.lock().unwrap();
            if let Some(t) = s.seqs.get_mut(&ch) {
                t.l1_balance = balance;
                t.l1_signers = signers;
                t.l1_accredited_keys = keys;
                t.l1_tip_slot = tip_slot;
                t.l1_tip_start_slot = tip_start_slot;
                t.l1_config_threshold = config_threshold;
                t.l1_withdraw_threshold = withdraw_threshold;
                // tip changed (or first sighting) => the sequencer settled a block
                if !tip.is_empty() && (t.last_tip.is_empty() || t.last_tip != tip) {
                    t.last_tip = tip;
                    t.tip_change_unix = now;
                }
            }
        }
        if let Some(url) = rpc_for.get(&ch) {
            if let Some(tip) = rpc_get_last_block_id(client, url).await {
                let mut s = app.inner.lock().unwrap();
                if let Some(t) = s.seqs.get_mut(&ch) {
                    t.seq_tip = Some(tip);
                }
            }
        }
    }
}

/// Query a sequencer's JSON-RPC `getLastBlockId` (its self-reported L2 tip).
async fn rpc_get_last_block_id(client: &Client, url: &str) -> Option<u64> {
    let body = json!({"jsonrpc":"2.0","method":"getLastBlockId","params":[],"id":1});
    let resp = client.post(url).json(&body).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    v.get("result").and_then(Value::as_u64)
}

// --- no-L1 sequencer block source ------------------------------------------
//
// A LEZ sequencer serves its own blocks over the same JSON-RPC: getLastBlockId
// (tip), getBlock(id) and getBlockRange(start,end) return the borsh `Block` body
// as a base64 string. base64-decoded, those bytes ARE the inscription bytes the L1
// path decodes - so we reuse decode_inscription/ingest/records_from verbatim, just
// with a different source. No L1 node required.

/// Decode standard base64 (ignoring `=` padding + whitespace) into bytes.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut nbits) = (0u32, 0u32);
    for &c in s.as_bytes() {
        if matches!(c, b'=' | b'\n' | b'\r' | b' ' | b'\t') {
            continue;
        }
        acc = (acc << 6) | val(c)? as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// A base64(borsh) block body -> raw inscription bytes.
fn block_b64_to_bytes(v: &Value) -> Option<Vec<u8>> {
    base64_decode(v.as_str()?)
}

/// `getBlock(id)` -> raw inscription bytes (None if absent/pruned/error).
async fn rpc_get_block(client: &Client, url: &str, id: u64) -> Option<Vec<u8>> {
    let body = json!({"jsonrpc":"2.0","method":"getBlock","params":[id],"id":1});
    let resp = client.post(url).json(&body).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    block_b64_to_bytes(v.get("result")?)
}

/// `getBlockRange(start,end)` -> [(id, bytes)]. None on RPC error (a missing/pruned id
/// in the range makes the sequencer error the whole call), so callers fall back to
/// per-id getBlock which tolerates gaps.
async fn rpc_get_block_range(
    client: &Client,
    url: &str,
    start: u64,
    end: u64,
) -> Option<Vec<(u64, Vec<u8>)>> {
    let body = json!({"jsonrpc":"2.0","method":"getBlockRange","params":[start, end],"id":1});
    let resp = client.post(url).json(&body).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    let arr = v.get("result")?.as_array()?;
    Some(
        arr.iter()
            .enumerate()
            .filter_map(|(i, item)| block_b64_to_bytes(item).map(|b| (start + i as u64, b)))
            .collect(),
    )
}

/// Fetch block ids `[start,end]` - one getBlockRange call, falling back to per-id
/// getBlock (tolerating pruned/missing ids) on range error. The per-id fallback runs
/// concurrently so a single missing id (e.g. no block 0 when genesis is 1) doesn't
/// serialize the whole chunk.
async fn seq_fetch_chunk(client: &Client, url: &str, start: u64, end: u64) -> Vec<(u64, Vec<u8>)> {
    if let Some(v) = rpc_get_block_range(client, url, start, end).await {
        if !v.is_empty() {
            return v;
        }
    }
    let mut out: Vec<(u64, Vec<u8>)> = futures::stream::iter(start..=end)
        .map(|id| async move { rpc_get_block(client, url, id).await.map(|b| (id, b)) })
        .buffer_unordered(16)
        .filter_map(|x| async move { x })
        .collect()
        .await;
    out.sort_by_key(|(id, _)| *id);
    out
}

/// Decode + ingest a fetched chunk of sequencer blocks into in-memory state, then
/// persist (one redb commit per chunk, each tx stamped with its own block_id).
async fn ingest_seq_chunk(app: &AppState, channel: &str, chunk: &[(u64, Vec<u8>)]) {
    if chunk.is_empty() {
        return;
    }
    let now = now_unix();
    let mut decoded: Vec<(String, u64, Decoded)> = Vec::new();
    {
        let mut s = app.inner.lock().unwrap();
        for (bid, bytes) in chunk {
            let ins = Value::String(hex::encode(bytes));
            if let Some(d) = decode_inscription(&ins) {
                ingest(&mut s, channel, Some(*bid), &d, now);
                let e = s.seqs.entry(channel.to_string()).or_default();
                // Sequencer-RPC source: every block the sequencer serves has been (or is
                // being) inscribed to the L1 - settlement is its whole job - so a
                // non-finalized block here is "on L1, finalizing" (Safe), never grey
                // "pending". The sequencer freezes/reports bedrock_status only as
                // Pending/Finalized (never Safe; confirmed on the live rc5 node), so lift
                // the Safe cursor to the ingested block id ourselves. `finalized_block_id`
                // still advances only from a genuine bedrock Finalized status (via ingest).
                // (Defensive: skip an undecodable block's garbage id - normal rc5 blocks
                // from getBlock decode fine.)
                if !d.undecodable {
                    raise_finality(e, d.block_id, false);
                }
                e.observe(&d, now);
                e.verify(&d);
                e.seq_tip = Some(e.latest_block_id);
                e.tip_change_unix = now;
                decoded.push((channel.to_string(), *bid, d));
            }
        }
    }
    if !decoded.is_empty() {
        persist_seq_blocks(app, &decoded).await;
        broadcast(app);
    }
}

/// Persist a batch of sequencer-sourced blocks (each stamped with its own block_id as
/// the slot - sequencer mode has no L1 slot). Mirrors persist_blocks but per-item.
async fn persist_seq_blocks(app: &AppState, items: &[(String, u64, Decoded)]) {
    let Some(db) = app.db.clone() else {
        return;
    };
    let mut recs = Vec::new();
    let now = now_unix();
    for (ch, bid, d) in items {
        recs.extend(records_from(ch, Some(*bid), d, now));
    }
    let mut top: HashMap<String, u64> = HashMap::new();
    for (ch, bid, _) in items {
        let e = top.entry(ch.clone()).or_insert(0);
        *e = (*e).max(*bid);
    }
    let (summaries, accts) = {
        let s = app.inner.lock().unwrap();
        let summaries: Vec<(String, SeqTrack)> = top
            .keys()
            .filter_map(|c| s.seqs.get(c).map(|t| (c.clone(), t.clone())))
            .collect();
        let mut seen = HashSet::new();
        let mut accts: Vec<(String, AcctBal)> = Vec::new();
        for r in &recs {
            for a in &r.accounts {
                if seen.insert(a.clone()) {
                    if let Some(b) = s.accounts.get(a) {
                        accts.push((a.clone(), b.clone()));
                    }
                }
            }
        }
        (summaries, accts)
    };
    let cursors: Vec<(String, u64)> = top.into_iter().collect();
    let elfs = collect_elfs(items.iter().map(|(_, _, d)| d));
    // Persist first, then broadcast (see persist_blocks): the live feed must not lead the
    // durable store the zone view + tx page read.
    match tokio::task::spawn_blocking(move || {
        db.commit(&recs, &summaries, &cursors, &accts)?;
        db.put_elfs(&elfs)?;
        anyhow::Ok(recs)
    })
    .await
    {
        Ok(Ok(recs)) => broadcast_txs(app, &recs),
        Ok(Err(e)) => eprintln!("store: seq commit error: {e:#}"),
        Err(e) => eprintln!("store: seq join error: {e}"),
    }
}

/// No-L1 ingest for one sequencer: backfill its blocks (full history, or the most
/// recent `window`) then poll getLastBlockId and ingest new blocks as they settle.
async fn sequencer_loop(
    client: Client,
    rpc_url: String,
    channel: String,
    full: bool,
    window: u64,
    app: AppState,
    generation: u64,
    // Running alongside an L1 read (L1 mode): don't clobber the L1 reachability/sync state,
    // and don't trust the L1-seeded `latest_block_id` (the L1 lags + carries only the channel
    // layer) - backfill the sequencer's zone blocks from its own floor so user txs are ingested.
    with_l1: bool,
) {
    const CHUNK: u64 = 256;
    let restored_latest = if with_l1 {
        0
    } else {
        app.inner
            .lock()
            .unwrap()
            .seqs
            .get(&channel)
            .map(|t| t.latest_block_id)
            .unwrap_or(0)
    };
    let mut backfilled = false;
    println!("sequencer source {}: {rpc_url}", short(&channel));

    while app.generation.load(Ordering::SeqCst) == generation {
        let Some(tip) = rpc_get_last_block_id(&client, &rpc_url).await else {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        if !with_l1 {
            let mut s = app.inner.lock().unwrap();
            s.l1.reachable = false; // no L1 in this mode
            s.l1.last_event_unix = now_unix();
        }
        // first pass: backfill from the floor; later passes: just the new tail
        let (mut next, _label) = if !backfilled {
            let floor = if full { 0 } else { tip.saturating_sub(window) };
            // resume forward from what we already have - unless the chain rolled back
            // below it (tip reset), in which case re-seed from the floor.
            let start = if restored_latest > 0 && restored_latest <= tip {
                restored_latest + 1
            } else {
                if restored_latest > tip {
                    eprintln!(
                        "sequencer {}: tip {tip} < stored {restored_latest} (rollback/reset) - re-seeding from {floor}",
                        short(&channel)
                    );
                }
                floor
            };
            (start, "backfill")
        } else {
            let have = app
                .inner
                .lock()
                .unwrap()
                .seqs
                .get(&channel)
                .map(|t| t.latest_block_id)
                .unwrap_or(0);
            (have + 1, "live")
        };
        while next <= tip {
            if app.generation.load(Ordering::SeqCst) != generation {
                return;
            }
            let end = (next + CHUNK - 1).min(tip);
            let chunk = seq_fetch_chunk(&client, &rpc_url, next, end).await;
            ingest_seq_chunk(&app, &channel, &chunk).await;
            next = end + 1;
        }
        backfilled = true;
        // Advance the L1-finality frontier: re-read a bounded chunk of blocks just above the
        // finalized threshold so their bedrock_status pending->Finalized flips are picked up
        // (ingest raises finalized_block_id). Re-ingest is idempotent (db dedups by hash).
        {
            let fin = app
                .inner
                .lock()
                .unwrap()
                .seqs
                .get(&channel)
                .map(|t| t.finalized_block_id)
                .unwrap_or(0);
            if fin + 1 <= tip {
                let to = (fin + CHUNK).min(tip);
                let chunk = seq_fetch_chunk(&client, &rpc_url, fin + 1, to).await;
                ingest_seq_chunk(&app, &channel, &chunk).await;
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Base58 of the fixed clock account id `b"/LEZ/ClockProgramAccount/0000001"`. The
/// clock program is a built-in that `getProgramIds` does NOT list, but every
/// sequencer maintains this account, so its `program_owner` is that sequencer's
/// clock program id - letting us auto-name the clock regardless of version skew.
const CLOCK_PROGRAM_ACCOUNT: &str = "4BdcjoXkq786TMWcBGGHqcxeLYMZmn17rL4eM9ZyRWNU";

/// `getAccount(account).program_owner` formatted as a 64-hex program id (matching tx
/// program labels), used to resolve a program id from a well-known account it owns.
async fn rpc_program_owner(client: &Client, url: &str, account: &str) -> Option<String> {
    let body = json!({"jsonrpc":"2.0","method":"getAccount","params":[account],"id":1});
    let resp = client.post(url).json(&body).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    let arr = v.get("result")?.get("program_owner")?.as_array()?;
    let hex: String = arr
        .iter()
        .filter_map(Value::as_u64)
        .flat_map(|w| (w as u32).to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect();
    (hex.len() == 64).then_some(hex)
}

/// Fetch a sequencer's `getProgramIds` registry and return {program_id_hex -> name},
/// where the hex is the `[u32;8]` id formatted the same way tx program labels are
/// (so it matches the `program` field stored on each transaction).
async fn rpc_get_program_ids(client: &Client, url: &str) -> Option<HashMap<String, String>> {
    let body = json!({"jsonrpc":"2.0","method":"getProgramIds","params":[],"id":1});
    let resp = client.post(url).json(&body).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    let obj = v.get("result")?.as_object()?;
    let mut out = HashMap::new();
    for (name, idv) in obj {
        // id is a `[u32;8]` array (serialize as LE bytes) or already a hex string.
        let hex: Option<String> = if let Some(arr) = idv.as_array() {
            Some(
                arr.iter()
                    .filter_map(Value::as_u64)
                    .flat_map(|w| (w as u32).to_le_bytes())
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            )
        } else {
            idv.as_str().map(|s| s.trim_start_matches("0x").to_ascii_lowercase())
        };
        if let Some(h) = hex {
            if h.len() == 64 {
                out.insert(h, name.clone());
            }
        }
    }
    Some(out)
}

async fn stream_loop(
    stream_client: Client,
    client: Client,
    base: String,
    app: AppState,
    focus: Option<BTreeSet<String>>,
    generation: u64,
) {
    let stream_url = format!("{base}/cryptarchia/events/blocks/stream");
    while app.generation.load(Ordering::SeqCst) == generation {
        match stream_client.get(&stream_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let mut bytes = resp.bytes_stream();
                let mut buf: Vec<u8> = Vec::new();
                while let Some(chunk) = bytes.next().await {
                    if app.generation.load(Ordering::SeqCst) != generation {
                        return;
                    }
                    let Ok(chunk) = chunk else { break };
                    buf.extend_from_slice(&chunk);
                    // a single ndjson event is small; if a (malicious/buggy) node streams
                    // megabytes with no newline, drop the connection rather than OOM.
                    if buf.len() > 4 * 1024 * 1024 {
                        eprintln!("blocks-stream: oversized line (>4MiB, no newline) - reconnecting");
                        break;
                    }
                    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = buf.drain(..=pos).collect();
                        let line = &line[..line.len().saturating_sub(1)];
                        if line.is_empty() {
                            continue;
                        }
                        if let Ok(ev) = serde_json::from_slice::<Value>(line) {
                            handle_event(&client, &base, &app, &ev, &focus, generation).await;
                        }
                    }
                }
            }
            Ok(resp) => eprintln!("blocks-stream HTTP {}", resp.status()),
            Err(e) => eprintln!("blocks-stream connect failed: {e}"),
        }
        if app.generation.load(Ordering::SeqCst) != generation {
            return;
        }
        // disconnected: refresh once and retry
        refresh_info(&client, &base, &app).await;
        broadcast(&app);
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// The header id carried by a stream event: v0.2.0 nests it at `block.header.id`;
/// 0.1.2 carried a top-level `block_id`. Empty/placeholder ids are treated as absent.
fn block_id_of(ev: &Value) -> Option<String> {
    let id = ev
        .get("block")
        .and_then(|b| b.get("header"))
        .and_then(|h| h.get("id"))
        .map(jhex)
        .or_else(|| ev.get("block_id").map(jhex))
        .unwrap_or_default();
    (!id.is_empty() && id != "?").then_some(id)
}

async fn handle_event(
    client: &Client,
    base: &str,
    app: &AppState,
    ev: &Value,
    focus: &Option<BTreeSet<String>>,
    generation: u64,
) {
    if app.generation.load(Ordering::SeqCst) != generation {
        return;
    }
    let now = now_unix();
    let tip_slot = jget_u64(ev, "tip_slot");
    let lib_slot = jget_u64(ev, "lib_slot");

    {
        let mut s = app.inner.lock().unwrap();
        s.l1.reachable = true;
        s.l1.fail_streak = 0;
        s.l1.last_event_unix = now;
        if let Some(ts) = tip_slot {
            if s.l1.prev_slot.is_none_or(|p| ts > p) {
                s.l1.last_advance_unix = now;
            }
            s.l1.prev_slot = Some(ts);
            s.l1.tip_slot = Some(ts);
        }
        if let Some(ls) = lib_slot {
            if s.l1.lib_slot.is_none_or(|p| ls > p) {
                s.l1.last_advance_unix = now;
            }
            s.l1.lib_slot = Some(ls);
        }
    }

    // v0.2.0 inlines the full block in the stream event (`ev.block`); use it directly.
    // As a safety net (e.g. an event variant that omits the inline block) fall back to
    // fetching by header id via the v0.2.0 route `GET /cryptarchia/blocks/:id`. (The old
    // 0.1.2 `POST /storage/block` is removed — that endpoint no longer exists.)
    let block: Option<Value> = match ev.get("block") {
        Some(b) if b.is_object() => Some(b.clone()),
        _ => match block_id_of(ev) {
            Some(id) => match get_json(client, &format!("{base}/cryptarchia/blocks/{id}")).await {
                EndpointResult::Ok(b) => Some(b),
                _ => None,
            },
            None => None,
        },
    };
    if let Some(block) = block {
        let slot = find_u64(&block, "slot");
        let mut found = Vec::new();
        collect_inscriptions(&block, &mut found);
        let mut decoded: Vec<(String, Decoded)> = Vec::new();
        {
            let mut s = app.inner.lock().unwrap();
            // This is a *live* L1 block off the stream: its inscriptions are on the L1 (at
            // least Safe). It's Finalized only once we know its slot is at/below `lib`; a
            // freshly streamed tip block (slot > lib) stays Safe until finality catches up.
            let lib = s.l1.lib_slot;
            let l1_final = matches!((slot, lib), (Some(sl), Some(l)) if sl <= l);
            for ri in found {
                let ch = ri.channel;
                if let Some(f) = focus {
                    if !f.contains(&ch) {
                        continue;
                    }
                }
                if let Some(d) = decode_inscription_with(&ri.value, ri.tx_hash.as_deref()) {
                    ingest(&mut s, &ch, slot, &d, now);
                    let e = s.seqs.entry(ch.clone()).or_default();
                    if !d.undecodable {
                        raise_finality(e, d.block_id, l1_final);
                    }
                    e.observe(&d, now);
                    e.verify(&d); // re-check accuracy on every new block
                    decoded.push((ch, d));
                }
            }
        }
        if !decoded.is_empty() {
            persist_blocks(app, slot, &decoded).await;
        }
    }
    broadcast(app);
}

/// Write freshly-decoded blocks (and the touched sequencers'/accounts' state) to
/// the durable store, off the async reactor and outside the state lock.
async fn persist_blocks(app: &AppState, slot: Option<u64>, decoded: &[(String, Decoded)]) {
    let Some(db) = app.db.clone() else {
        return;
    };
    let now = now_unix();
    let mut recs = Vec::new();
    for (ch, d) in decoded {
        recs.extend(records_from(ch, slot, d, now));
    }
    let channels: HashSet<String> = decoded.iter().map(|(c, _)| c.clone()).collect();
    let (summaries, accts) = {
        let s = app.inner.lock().unwrap();
        let summaries: Vec<(String, SeqTrack)> = channels
            .iter()
            .filter_map(|c| s.seqs.get(c).map(|t| (c.clone(), t.clone())))
            .collect();
        let mut seen = HashSet::new();
        let mut accts: Vec<(String, AcctBal)> = Vec::new();
        for r in &recs {
            for a in &r.accounts {
                if seen.insert(a.clone()) {
                    if let Some(b) = s.accounts.get(a) {
                        accts.push((a.clone(), b.clone()));
                    }
                }
            }
        }
        (summaries, accts)
    };
    let cursors: Vec<(String, u64)> = match slot {
        Some(sl) => channels.iter().map(|c| (c.clone(), sl)).collect(),
        None => Vec::new(),
    };
    let elfs = collect_elfs(decoded.iter().map(|(_, d)| d));
    // Persist to the durable store FIRST, then push these new txs to clients - so a tx
    // never appears in the live feed before it's in the store that the zone view + tx page
    // read (otherwise the home feed shows txs a zone fetch / /api/tx can't find yet).
    match tokio::task::spawn_blocking(move || {
        db.commit(&recs, &summaries, &cursors, &accts)?;
        db.put_elfs(&elfs)?;
        anyhow::Ok(recs)
    })
    .await
    {
        Ok(Ok(recs)) => broadcast_txs(app, &recs),
        Ok(Err(e)) => eprintln!("store: stream commit error: {e:#}"),
        Err(e) => eprintln!("store: stream join error: {e}"),
    }
}

/// Extract (deploy_tx_hash, guest_elf_bytes) pairs from decoded blocks, for persisting
/// program-deployment ELFs separately from the (small) tx feed records.
fn collect_elfs<'a>(blocks: impl Iterator<Item = &'a Decoded>) -> Vec<(String, Vec<u8>)> {
    blocks
        .flat_map(|d| d.txs.iter())
        .filter(|t| !t.deploy_bytecode.is_empty())
        .map(|t| (t.hash.clone(), t.deploy_bytecode.clone()))
        .collect()
}

// --- HTTP handlers ---------------------------------------------------------

async fn index(State(app): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    if app.config.lock().unwrap().is_configured() {
        // inject the request origin so social/share (og:) URLs are absolute regardless
        // of where this is deployed.
        let origin = request_origin(&headers);
        Html(
            DASH_HTML
                .replace("{{ORIGIN}}", &origin)
                .replace("{{CHANNEL_ALIASES}}", &channel_alias_js()),
        )
        .into_response()
    } else {
        // /setup is token-gated, so don't redirect there - tell the operator to run setup.
        Html(NOT_CONFIGURED_HTML).into_response()
    }
}

/// A JS object literal `{"<channel hex>":"<display name>", ...}` of the known channel
/// display aliases, injected into the dashboard page so any channel id it renders (list,
/// header, per-channel labels) can show its friendly name. Same source as `channel_alias`.
fn channel_alias_js() -> String {
    let pairs: Vec<String> = crate::CHANNEL_ALIASES
        .iter()
        .filter_map(|(id, _)| {
            channel_alias(id).map(|name| {
                format!(
                    "{}:{}",
                    serde_json::to_string(id).unwrap_or_default(),
                    serde_json::to_string(name).unwrap_or_default()
                )
            })
        })
        .collect();
    format!("{{{}}}", pairs.join(","))
}

/// `scheme://host` for absolute share URLs, honoring a reverse proxy's
/// `X-Forwarded-Proto` / `X-Forwarded-Host`.
fn request_origin(h: &axum::http::HeaderMap) -> String {
    let pick = |v: &axum::http::HeaderValue| v.to_str().ok().map(|s| s.split(',').next().unwrap_or(s).trim().to_string());
    let host = h
        .get("x-forwarded-host")
        .or_else(|| h.get(axum::http::header::HOST))
        .and_then(pick)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "127.0.0.1:8088".into());
    let scheme = h
        .get("x-forwarded-proto")
        .and_then(pick)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http".into());
    format!("{scheme}://{host}")
}

const NOT_CONFIGURED_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>zonescan</title><link rel="icon" type="image/png" href="/logo.png">
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f4f5;color:#18181b;
font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}.card{max-width:460px;padding:36px 30px;text-align:center}
img{width:56px;height:56px}h1{font-size:20px;margin:14px 0 6px}p{color:#6e6e77;margin:6px 0}
code{background:#e6e6e9;padding:2px 7px;border-radius:5px;font:13px ui-monospace,Menlo,monospace}</style></head>
<body><div class="card"><img src="/logo.png" alt=""><h1>zonescan</h1>
<p>Not configured yet.</p>
<p>Run <code>zonescan setup</code> in your terminal and open the one-time link it prints
to point it at an L1 node or a sequencer.</p>
</div></body></html>"#;

async fn admin_page() -> Html<&'static str> {
    Html(ADMIN_HTML)
}

/// Validate a posted config before applying it (scheme + host:port shape). Loopback
/// is intentionally allowed - pointing at a local sequencer/L1 is the common case.
fn validate_config(cfg: &Config) -> std::result::Result<(), String> {
    let url = cfg.l1_node_url.trim();
    if !url.is_empty() && !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("l1_node_url must start with http:// or https://".into());
    }
    if let Some(s) = cfg.socks5.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if s.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).is_none() {
            return Err("socks5 must be host:port".into());
        }
    }
    for s in &cfg.sequencers {
        let r = s.rpc_url.trim();
        if !r.is_empty() && !(r.starts_with("http://") || r.starts_with("https://")) {
            return Err("sequencer rpc_url must start with http:// or https://".into());
        }
    }
    Ok(())
}

/// The navbar logo, embedded in the binary (kept self-contained for npx/docker).
async fn logo_png() -> impl IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/png"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        &include_bytes!("../logo-nav.png")[..],
    )
}

async fn api_config_get(State(app): State<AppState>, req: axum::extract::Request) -> Json<Config> {
    let mut cfg = app.config.lock().unwrap().clone();
    // The read path is public (dashboard) - redact proxy + sequencer rpc endpoints
    // unless the caller holds the setup token.
    if !request_token_ok(&app.admin_token, &req) {
        if !cfg.l1_node_url.trim().is_empty() {
            cfg.l1_node_url = "***".into();
        }
        if cfg.socks5.as_deref().map(str::trim).is_some_and(|s| !s.is_empty()) {
            cfg.socks5 = Some("***".into());
        }
        for s in &mut cfg.sequencers {
            if !s.rpc_url.trim().is_empty() {
                s.rpc_url = "***".into();
            }
        }
    }
    Json(cfg)
}

async fn api_config_post(State(app): State<AppState>, Json(cfg): Json<Config>) -> Response {
    if let Err(msg) = validate_config(&cfg) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "ok": false, "error": msg }))).into_response();
    }
    {
        let mut c = app.config.lock().unwrap();
        *c = cfg.clone();
    }
    if let Err(e) = save_config(&app.config_path, &cfg) {
        eprintln!("failed to save config: {e:#}");
    }
    if let Err(e) = apply_config(&app).await {
        eprintln!("failed to apply config: {e:#}");
    }
    Json(json!({ "ok": true, "configured": cfg.is_configured() })).into_response()
}

/// The {program_id_hex -> name} registry resolved from sequencers' `getProgramIds`,
/// used by the UI to show human program names instead of raw 64-hex ids.
/// The full program id(hex) -> name map: rc4 built-ins (always known from the decode
/// build) + the getProgramIds registry + user-assigned names. Precedence: user names >
/// registry > built-ins. Built-ins make names work with no reachable sequencer RPC and
/// resolve ids stored as raw hex by an older build (e.g. the clock `625e7b…`).
/// rc3 LEZ built-in program ids (hex) -> name. The rc4 build we link doesn't know these,
/// so baking them in lets rc3 sequencers (e.g. prod `8101`) resolve + decode offline
/// alongside rc4 - purely additive (cryptographic ids never collide with rc4's).
// Program ids are the risc0 image id ([u32;8]) serialized as LITTLE-ENDIAN bytes - the
// on-chain / `getProgramIds` / wallet convention (matches `program_id_hex`).
const RC3_PROGRAMS: &[(&str, &str)] = &[
    ("6d1ec77d426db847e2a37eb964b78d7870b89f17fc7f2537c0e50046bd8a8150", "token"),
    ("a2cb551b201f93227167cdd38a0c081c2b771cd4fdc95ed950167132b2e39fbe", "amm"),
    ("f6210ca6cacf7c2448e90ffa79fe9e26ff9bcf92690a61909df37ec031c6adc2", "clock"),
    ("beba346bf12ae2105b301aa7af0f922d2d67891660c52a6bf30968facbc2aacf", "pinata"),
    ("2c50b34c3709ca40f2d3339d4282e516a8d5ea8324cbc900d55fc4fef9d9f4e4", "pinata_token"),
    ("a96e088942d7fc09afc7b1db5221558c67f772ac8130d04df1c086dc07ab8b7b", "authenticated_transfer"),
];

/// rc5 (Testnet v0.2) LEZ built-in program ids -> name, in the canonical LITTLE-ENDIAN
/// byte form (matches `program_id_hex` / the sequencer `getProgramIds` registry / wallet).
/// The 12 non-clock natives are the deployed zone's own build (`netcup-program-methods.rs`,
/// verified against wallet txs + `getProgramIds`). The CLOCK is the EMPIRICAL id read from
/// a live settled block (`884e693a…`); the source-tree clock (`e23158e6…`) differs and is
/// kept only as a fallback for a differently-built rc5 zone. User-deployed programs (not
/// natives) are not here and correctly render as raw hex.
const RC5_PROGRAMS: &[(&str, &str)] = &[
    // deployed clock (empirical, from a live settled block)
    ("884e693a302d57de1ac4c405ca5bea1df707d1de11d9f87de51b78845aa98e63", "clock"),
    // 12 non-clock natives (netcup build, LE-bytes)
    ("c4584a559312f876bbde4248b1daf95f6fc895a42171734d3ffd32940c0adf24", "token"),
    ("5d75823a711b071a6da5685c84300a4d4e2fcbada25b95889ee11d88c84b6791", "amm"),
    ("e4870e1f7ef3df44a22bec5e00d03f7d6ad5fbca7a87a56b38be9d85e2b932a4", "ata"),
    ("9b3c8c8b84a2cab7ee51fd9e30f528a3bb51ca54ab0904a5f1ba7693fe874bec", "pinata"),
    ("14a015ff3ee264a3805bd96cdbaa2a01fdaa92a748903d83e1f776b00036882f", "pinata_token"),
    ("d9a19237236822b1f8100576ebd19a19f74178f99e284c983a4ac44acbd5b472", "authenticated_transfer"),
    ("af574d16b236ab9849f0859b6efdaf0fcb8a70dcf7b8adb95458b7af769f34a2", "privacy_preserving_circuit"),
    ("7901368d63e50c4ae7b9197feb4bb17266b4023b8700c6ef5ffee6802d468dd5", "bridge"),
    ("961277217aa4b6f77ba8fcceb2795247570d8560737f7eb7674cd5278170190c", "faucet"),
    ("f8c762a3b9327f72a379bcb1c9aeb77fbb3f9ac59c621dbf5635f5c114a2e481", "genesis_supply_account"),
    ("bba2d637a24891b1b8cc00149dee801d99d388e78e2516b935ce8796216c0397", "genesis_supply_private_account"),
    ("a8d1ec6d803dfc54a55d3cf576388a7d461b02a38bd4cd87ebf30837a2f1df07", "vault"),
    // source-tree rc5 clock fallback (a zone built straight from v0.2.0-rc5 uses this)
    ("e23158e6e7b4aeeee8d3036eafd7c759e51d8a094d827b925710ba21deff8f46", "clock"),
    // --- genesis / test programs, identified by on-chain instruction FINGERPRINT (best
    // guess). The deployed zone rebuilt these guests, so their image ids match no local
    // source artifact (verified: e.g. the source `time_locked_transfer` computes to
    // 4badfd16.., but the deployed id is 2ac6039d..). Named from the instruction shape +
    // genesis balances; the remaining unidentified ids render cleanly as raw hex.
    ("c316e2bed1d90687b35b80d460d35e7fe40130bbd2563cf19ee12e0e06c74508", "genesis_supply_bridge"), // instr [1, 1000000]
    ("40acaa4547c36a0e243d1bcb3e880b7fa3fd2175002a3977fa5b7299c5e5754f", "genesis_supply"), // instr [1, 20000]
    ("2ac6039da4df524ac8448f5b41b56887934f6d7081279a70042b072625bc67e1", "time_locked_transfer"), // instr [3, 86400000] = 1 day (ms)
    ("df89eefa733d4e4b26ec2094b593c1a719a7ff99885f5a4f69c4a9e89a888d05", "validity_window"), // instr [3, 15, 30, 45, 60]
];

/// Set from `Config.skip_clock`; when true, clock-program txs aren't stored/indexed.
static SKIP_CLOCK: AtomicBool = AtomicBool::new(false);

/// Whether a program label/id is the clock (across builds), so it can be skipped/hidden.
fn is_clock_program(p: &str) -> bool {
    p == "clock"
        || RC3_PROGRAMS.iter().any(|(id, name)| *name == "clock" && *id == p)
        || RC5_PROGRAMS.iter().any(|(id, name)| *name == "clock" && *id == p)
}

/// Which LEZ build a sequencer runs, inferred from a program label/id it inscribes.
/// The rc4 build (the one we link) labels its OWN built-ins by name, so a known name
/// means rc4; an rc3 built-in only ever appears as its raw hex id.
fn lez_version(program: &str) -> Option<&'static str> {
    if matches!(
        program,
        "token" | "amm" | "clock" | "ata" | "pinata" | "pinata_token" | "authenticated_transfer"
    ) {
        return Some("rc4");
    }
    if RC5_PROGRAMS.iter().any(|(id, _)| *id == program) {
        return Some("rc5");
    }
    if RC3_PROGRAMS.iter().any(|(id, _)| *id == program) {
        return Some("rc3");
    }
    None
}

fn program_name_map(app: &AppState) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = crate::builtin_program_ids().into_iter().collect();
    for (id, name) in RC3_PROGRAMS.iter().chain(RC5_PROGRAMS) {
        m.entry((*id).to_string()).or_insert_with(|| (*name).to_string());
    }
    for (k, v) in app.programs.lock().unwrap().iter() {
        m.insert(k.clone(), v.clone());
    }
    for p in &app.config.lock().unwrap().program_names {
        let id = p.id.trim().trim_start_matches("0x").to_ascii_lowercase();
        let name = p.name.trim();
        if id.len() == 64 && !name.is_empty() {
            m.insert(id, name.to_string());
        }
    }
    m
}

async fn api_programs(State(app): State<AppState>) -> Json<HashMap<String, String>> {
    Json(program_name_map(&app))
}

/// A program id looks "raw" (unnamed) when it's the 64-hex image id, not a human built-in name.
fn is_raw_program_id(p: &str) -> bool {
    p.len() >= 40 && p.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Build the classifier's reference profiles: the source-derived built-in interfaces (primary)
/// augmented with runtime profiles LEARNED from the programs we can already name. `samples` is
/// the store aggregation (id -> invocation samples); `names` maps a known id -> its name. Only
/// ids with a known name contribute learned profiles, so an unrecognized program is never used
/// to define the reference it's later matched against.
fn build_reference_profiles(
    samples: &[(String, Vec<classify::Sample>)],
    names: &HashMap<String, String>,
) -> Vec<classify::Profile> {
    use std::collections::HashMap as Map;
    let mut refs = classify::source_profiles();
    // Group named ids' samples by NAME so several ids sharing a name (e.g. rc3/rc5 auth_transfer)
    // pool into one learned profile.
    let mut by_name: Map<String, Vec<classify::Sample>> = Map::new();
    for (id, ss) in samples {
        if let Some(name) = names.get(id) {
            by_name.entry(name.clone()).or_default().extend(ss.iter().cloned());
        }
    }
    for (name, ss) in by_name {
        if let Some(p) = classify::learn_profile(&name, &ss) {
            refs.push(p);
        }
    }
    refs
}

/// Recompute the best-guess name map for unrecognized programs from the durable store, and
/// store it in `app.guesses`. Learns reference profiles from named programs' on-chain txs +
/// the source-derived built-ins, then classifies every id no registry knows.
async fn refresh_guesses(app: &AppState) {
    let Some(db) = app.db.clone() else { return };
    let raw = match tokio::task::spawn_blocking(move || db.program_samples(48)).await {
        Ok(Ok(v)) => v,
        _ => return,
    };
    // Convert store tuples -> classifier samples.
    let samples: Vec<(String, Vec<classify::Sample>)> = raw
        .into_iter()
        .map(|(id, rows)| {
            let ss = rows
                .into_iter()
                .map(|(accts, kind, words)| {
                    classify::Sample::new(classify::Kind::from_str(&kind), accts, words)
                })
                .collect();
            (id, ss)
        })
        .collect();

    let names = program_name_map(app);
    let refs = build_reference_profiles(&samples, &names);

    let mut out: HashMap<String, classify::Guess> = HashMap::new();
    for (id, ss) in &samples {
        // Only guess for ids no registry names, and only for raw 64-hex ids (skip built-in
        // names, which are already resolved).
        if names.contains_key(id) || !is_raw_program_id(id) {
            continue;
        }
        if let Some(g) = classify::classify(ss, &refs) {
            out.insert(id.clone(), g);
        }
    }
    *app.guesses.lock().unwrap() = out;
}

/// The best-guess name for one program id, if the classifier surfaced one above threshold.
fn program_guess(app: &AppState, id: &str) -> Option<classify::Guess> {
    app.guesses.lock().unwrap().get(id).cloned()
}

/// The best-guess map (id -> guess), for the UI to render `≈ name` on unrecognized programs.
async fn api_program_guesses(State(app): State<AppState>) -> Json<HashMap<String, classify::Guess>> {
    Json(app.guesses.lock().unwrap().clone())
}

/// Decode `words[pos..]` per the schema type `t` (same grammar as the UI decoder),
/// returning the next word index - or None on overrun, unknown type, no progress, or
/// invalid UTF-8. A schema is "correct" for a sample iff this returns Some(words.len())
/// (it consumes exactly the instruction, no leftover and no overrun).
fn schema_decode(words: &[u32], t: &Value, pos: usize, depth: u32) -> Option<usize> {
    if depth > 64 {
        return None;
    }
    if let Some(name) = t.as_str() {
        return match name {
            "u8" | "u16" | "u32" | "bool" => (pos + 1 <= words.len()).then_some(pos + 1),
            "u64" => (pos + 2 <= words.len()).then_some(pos + 2),
            "u128" => (pos + 4 <= words.len()).then_some(pos + 4),
            "string" => {
                let n = *words.get(pos)? as usize;
                let nw = 1 + n.div_ceil(4);
                if pos + nw > words.len() {
                    return None;
                }
                let mut b = Vec::with_capacity(n);
                for i in 0..n {
                    b.push((words[pos + 1 + i / 4] >> ((i % 4) * 8)) as u8);
                }
                std::str::from_utf8(&b).ok().map(|_| pos + nw)
            }
            "bytes" => {
                let n = *words.get(pos)? as usize;
                (pos + 1 + n <= words.len()).then_some(pos + 1 + n)
            }
            _ => None,
        };
    }
    let obj = t.as_object()?;
    if let Some(et) = obj.get("vec") {
        let n = *words.get(pos)? as usize;
        let mut p = pos + 1;
        for _ in 0..n {
            let np = schema_decode(words, et, p, depth + 1)?;
            if np <= p {
                return None; // a zero-width element type would loop forever
            }
            p = np;
        }
        return Some(p);
    }
    if let Some(arr) = obj.get("array").and_then(|a| a.as_array()) {
        let et = arr.first()?;
        let n = arr.get(1)?.as_u64()? as usize;
        let mut p = pos;
        for _ in 0..n {
            p = schema_decode(words, et, p, depth + 1)?;
        }
        return Some(p);
    }
    if let Some(fields) = obj.get("struct").and_then(|s| s.as_array()) {
        let mut p = pos;
        for f in fields {
            p = schema_decode(words, f.get("type")?, p, depth + 1)?;
        }
        return Some(p);
    }
    if let Some(variants) = obj.get("enum").and_then(|e| e.as_array()) {
        let vi = *words.get(pos)? as usize;
        let v = variants.get(vi)?;
        let mut p = pos + 1;
        if let Some(flds) = v.get("fields").and_then(|f| f.as_array()) {
            for f in flds {
                p = schema_decode(words, f.get("type")?, p, depth + 1)?;
            }
        }
        return Some(p);
    }
    None
}

/// How many of `samples` a schema decodes exactly (full consumption) → (passed, tested).
fn validate_schema(samples: &[Vec<u32>], schema: &Value) -> (usize, usize) {
    let passed = samples
        .iter()
        .filter(|s| !s.is_empty() && schema_decode(s, schema, 0, 0) == Some(s.len()))
        .count();
    (passed, samples.len())
}

/// Deployer-supplied instruction schemas (program id hex -> instruction type), used by
/// the UI to typed-decode custom-program instructions.
async fn api_schemas(State(app): State<AppState>) -> Json<HashMap<String, Value>> {
    let mut m = HashMap::new();
    for s in &app.config.lock().unwrap().program_schemas {
        let id = s.id.trim().trim_start_matches("0x").to_ascii_lowercase();
        if id.len() == 64 && !s.instruction.is_null() {
            m.insert(id, s.instruction.clone());
        }
    }
    Json(m)
}

#[derive(serde::Deserialize)]
struct SchemaSubmit {
    /// a channel/sequencer where the program is used (for fetching real samples).
    #[serde(default)]
    channel: String,
    program_id: String,
    instruction: Value,
    /// validate only, don't store.
    #[serde(default)]
    dry: bool,
}

/// Open schema submission: anyone can propose an instruction schema for a program. It's
/// accepted only if it decodes the program's REAL on-chain instructions exactly (full
/// consumption, valid UTF-8) - so a wrong schema is rejected automatically. Display-only,
/// so this is safe to leave open; first valid schema wins (admin can override).
async fn api_schema_submit(
    State(app): State<AppState>,
    Json(req): Json<SchemaSubmit>,
) -> Json<Value> {
    let id = req.program_id.trim().trim_start_matches("0x").to_ascii_lowercase();
    if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Json(json!({"ok": false, "error": "program id must be 64 hex chars"}));
    }
    // real instruction samples for this program from the store (per-channel index).
    let samples: Vec<Vec<u32>> = match app.db.clone() {
        Some(db) => {
            let (ch, lbl) = (req.channel.clone(), id.clone());
            match tokio::task::spawn_blocking(move || db.program(&ch, &lbl, 80)).await {
                Ok(Ok((txs, _))) => {
                    let mut seen = std::collections::HashSet::new();
                    txs.into_iter()
                        .map(|t| t.instruction_data)
                        .filter(|d| !d.is_empty() && seen.insert(d.clone()))
                        .take(40)
                        .collect()
                }
                _ => vec![],
            }
        }
        None => vec![],
    };
    if samples.is_empty() {
        return Json(json!({"ok": false,
            "error": "no on-chain instructions found for this program on that sequencer to validate against"}));
    }
    let (passed, tested) = validate_schema(&samples, &req.instruction);
    let valid = passed == tested;
    let exists = {
        let c = app.config.lock().unwrap();
        c.program_schemas
            .iter()
            .any(|s| s.id.trim().trim_start_matches("0x").to_ascii_lowercase() == id)
    };
    let mut stored = false;
    if valid && !req.dry && !exists {
        {
            let mut c = app.config.lock().unwrap();
            c.program_schemas.push(ProgSchema { id: id.clone(), instruction: req.instruction.clone() });
        }
        let snap = app.config.lock().unwrap().clone();
        if let Err(e) = save_config(&app.config_path, &snap) {
            eprintln!("schema submit: save failed: {e:#}");
        }
        stored = true;
    }
    Json(json!({
        "ok": true, "valid": valid, "passed": passed, "tested": tested,
        "stored": stored, "already_exists": exists,
    }))
}

async fn api_state(State(app): State<AppState>) -> Json<Snapshot> {
    let db_total = app.db.as_ref().map(|d| d.tx_total());
    let s = app.inner.lock().unwrap();
    Json(build_snapshot(&s, db_total))
}

#[derive(serde::Deserialize)]
struct TxQuery {
    q: Option<String>,
    kind: Option<String>,
    channel: Option<String>,
    /// filter to a program by human name (e.g. "token") - resolved to its id(s).
    program_name: Option<String>,
    /// filter to a single program id (for program pages).
    program: Option<String>,
    /// filter privacy-preserving txs by operation: shield / deshield / private-send.
    subtype: Option<String>,
    /// multi-select Type filter: comma-separated computed types
    /// (token, authenticated_transfer, clock, shield, deshield, amm, ata, pinata, deploy).
    types: Option<String>,
    /// feed sort: "oldest" = oldest-first; anything else (default) = newest-first.
    sort: Option<String>,
    /// show clock-program txs (default off - the clock ticks every block). Accepts
    /// "1"/"true"/"on" (string, since urlencoded bools only parse true/false).
    clock: Option<String>,
    /// pagination cursor: return txs strictly older than (before_ts, before_block, before_hash).
    before_ts: Option<u64>,
    before_block: Option<u64>,
    before_hash: Option<String>,
    limit: Option<usize>,
}

/// Filtered, newest-first transaction feed. `q` is a free-text search across tx
/// hash, program, accounts, nullifier/commitment digests, block id and channel.
/// Attach the resolved token `amount` + `token` ticker to a tx's JSON for token / ATA /
/// native transfers (e.g. `"amount":"250","token":"GOLD"`), so the feed + tx page can
/// render "GOLD 250" without a per-row lookup on the client.
/// Render a raw inscription's payload bytes for the tx-detail: `(Some(text), hex)` when the
/// bytes are printable UTF-8 (so the guest's rows read e.g. "dweb-via-paradox #2 …"), else
/// `(None, hex)` so the UI falls back to a hex dump.
fn raw_payload_repr(bytes: &[u8]) -> (Option<String>, String) {
    let hex = hex::encode(bytes);
    let text = std::str::from_utf8(bytes)
        .ok()
        .filter(|s| {
            !s.is_empty() && s.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        })
        .map(str::to_string);
    (text, hex)
}

fn enrich_tx(app: &AppState, rec: &TxRecord) -> Value {
    let mut v = serde_json::to_value(rec).unwrap_or(Value::Null);
    // The raw payload can be sizeable; list rows don't need it (they only badge "raw"). It's
    // re-surfaced as raw_text/raw_hex on the tx-detail (enrich_tx_detail).
    if let Value::Object(o) = &mut v {
        o.remove("raw_payload");
    }
    if let (Value::Object(o), Some(db)) = (&mut v, app.db.as_ref()) {
        let (amount, token) = db.token_op(rec);
        if let Some(a) = amount {
            o.insert("amount".into(), json!(a));
        }
        if let Some(t) = token {
            o.insert("token".into(), json!(t));
        }
    }
    // Attach a best-guess program name for an unrecognized (raw-id) program, so the row can
    // render `≈ name` distinctly from a verified name. Only for ids no registry knows.
    if let Value::Object(o) = &mut v {
        if let Some(p) = rec.program.as_deref().filter(|p| is_raw_program_id(p)) {
            if let Some(g) = program_guess(app, p) {
                o.insert("program_guess".into(), json!(g));
            }
        }
    }
    v
}

/// For the tx-detail: annotate each account that maps to a known token with its symbol +
/// role, so a token tag is visibly SOURCED (e.g. "EvBnxw… — GOLD (definition)") - reusing
/// the same resolve_token map that produced the tag.
fn token_accounts_json(app: &AppState, rec: &TxRecord) -> Vec<Value> {
    let Some(db) = app.db.as_ref() else {
        return vec![];
    };
    rec.accounts
        .iter()
        .filter_map(|a| {
            db.account_token(a)
                .map(|(sym, role)| json!({"account": a, "symbol": sym, "role": role}))
        })
        .collect()
}

/// tx-detail enrichment: `enrich_tx` (token name+amount) plus the per-account token
/// annotations (which account sourced the tag).
fn enrich_tx_detail(app: &AppState, rec: &TxRecord) -> Value {
    let mut v = enrich_tx(app, rec);
    let ta = token_accounts_json(app, rec);
    if let Value::Object(o) = &mut v {
        if !ta.is_empty() {
            o.insert("token_accounts".into(), json!(ta));
        }
        // For a raw inscription: surface the actual content (UTF-8 text and/or a hex dump).
        if rec.kind == "raw" && !rec.raw_payload.is_empty() {
            let (text, hex) = raw_payload_repr(&rec.raw_payload);
            o.insert("raw_len".into(), json!(rec.raw_payload.len()));
            o.insert("raw_hex".into(), json!(hex));
            if let Some(t) = text {
                o.insert("raw_text".into(), json!(t));
            }
        }
    }
    v
}

async fn api_txs(State(app): State<AppState>, Query(q): Query<TxQuery>) -> Json<Vec<Value>> {
    let limit = q.limit.unwrap_or(150).min(1000);
    let needle = q.q.as_deref().map(str::to_string).filter(|n| !n.is_empty());
    let kind = q.kind.as_deref().filter(|k| !k.is_empty() && *k != "all").map(str::to_string);
    let chan = q.channel.as_deref().filter(|c| !c.is_empty()).map(str::to_string);
    // merged id->name map (built-ins + registry + user names), so name-based filtering
    // and clock-hiding work for txs stored as raw hex by an older build too.
    let pmap = program_name_map(&app);
    // resolve a program-name filter (e.g. "token") to the matching program id(s) - plus
    // the name itself, since rc4-decoded txs store the name directly in `program`.
    let progs: Option<Vec<String>> = if let Some(pid) =
        q.program.as_deref().map(str::trim).filter(|s| !s.is_empty())
    {
        Some(vec![pid.to_string()])
    } else {
        q.program_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|name| {
                let mut ids: Vec<String> = pmap
                    .iter()
                    .filter(|(_, n)| n.as_str() == name)
                    .map(|(h, _)| h.clone())
                    .collect();
                ids.push(name.to_string());
                ids
            })
    };

    // multi-select Type filter: list of computed types to include.
    let types: Option<Vec<String>> = q.types.as_deref().map(|s| {
        s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect::<Vec<_>>()
    }).filter(|v| !v.is_empty());
    let types_has_clock = types.as_ref().is_some_and(|t| t.iter().any(|x| x == "clock"));
    let oldest = q.sort.as_deref() == Some("oldest");

    // hide clock-program txs unless ?clock=1 (they tick every block and flood the feed),
    // or "clock" is explicitly selected in the Type filter.
    let show_clock = types_has_clock
        || q.clock.as_deref().is_some_and(|c| matches!(c, "1" | "true" | "on" | "yes"));
    let exclude: Option<Vec<String>> = (!show_clock).then(|| {
        let mut ex = vec!["clock".to_string()];
        ex.extend(
            pmap.iter()
                .filter(|(_, n)| n.as_str() == "clock")
                .map(|(h, _)| h.clone()),
        );
        ex
    });
    let after: Option<(u64, u64, String)> = match (q.before_block, q.before_hash.as_deref()) {
        (Some(b), Some(h)) if !h.is_empty() => Some((q.before_ts.unwrap_or(0), b, h.to_string())),
        _ => None,
    };

    let subt = q.subtype.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);

    // durable store first (full history); fall back to the in-memory feed.
    if let Some(db) = app.db.clone() {
        let (c, k, st, n, pr, ex, af, ty) = (
            chan.clone(), kind.clone(), subt.clone(), needle.clone(), progs.clone(), exclude.clone(), after.clone(), types.clone(),
        );
        let res = tokio::task::spawn_blocking(move || {
            db.feed(&db::FeedOpts {
                channel: c.as_deref(),
                kind: k.as_deref(),
                subtype: st.as_deref(),
                types: ty.as_deref(),
                q: n.as_deref(),
                programs: pr.as_deref(),
                exclude: ex.as_deref(),
                after: af.as_ref().map(|(ts, b, h)| (*ts, *b, h.as_str())),
                oldest,
                limit,
            })
        })
        .await;
        if let Ok(Ok(v)) = res {
            return Json(v.iter().map(|r| enrich_tx(&app, r)).collect());
        }
    }

    let nlow = needle.as_deref().map(str::to_ascii_lowercase);
    let mut passed = after.is_none();
    let s = app.inner.lock().unwrap();
    let out: Vec<TxRecord> = s
        .txs
        .iter()
        .filter(|t| kind.as_deref().is_none_or(|k| t.kind == k))
        .filter(|t| subt.as_deref().is_none_or(|st| t.subtype == st))
        .filter(|t| match &types {
            Some(ts) => {
                let rt = if t.kind == "raw" {
                    "raw"
                } else if t.kind == "deploy" {
                    "deploy"
                } else if t.kind == "private" {
                    if t.subtype == "shield" || t.subtype == "deshield" { t.subtype.as_str() } else { "authenticated_transfer" }
                } else {
                    match t.program.as_deref() {
                        Some(p) if p.len() >= 40 && p.bytes().all(|b| b.is_ascii_hexdigit()) => "program",
                        Some(p) => p,
                        None => "public",
                    }
                };
                ts.iter().any(|x| x == rt)
            }
            None => true,
        })
        .filter(|t| match &progs {
            Some(ps) => t.program.as_deref().is_some_and(|p| ps.iter().any(|x| x == p)),
            None => true,
        })
        .filter(|t| match &exclude {
            Some(ex) => !t.program.as_deref().is_some_and(|p| ex.iter().any(|x| x == p)),
            None => true,
        })
        .filter(|t| {
            // pagination cursor: skip everything up to and including (before_hash).
            if passed {
                return true;
            }
            if after.as_ref().is_some_and(|(_, _, h)| *h == t.hash) {
                passed = true;
            }
            false
        })
        .filter(|t| chan.as_deref().is_none_or(|c| t.channel == c))
        .filter(|t| match &nlow {
            None => true,
            Some(n) => {
                let n = n.as_str();
                t.hash.contains(n)
                    || t.program.as_deref().is_some_and(|p| p.to_ascii_lowercase().contains(n))
                    || t.accounts.iter().any(|a| a.to_ascii_lowercase().contains(n))
                    || t.nullifiers.iter().any(|x| x.contains(n))
                    || t.commitments.iter().any(|x| x.contains(n))
                    || t.block_id.to_string() == n
                    || t.channel.contains(n)
            }
        })
        .take(limit)
        .cloned()
        .collect();
    Json(out.iter().map(|r| enrich_tx(&app, r)).collect())
}

async fn api_tx(
    State(app): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    if let Some(db) = app.db.clone() {
        let h = hash.clone();
        if let Ok(Ok(Some(t))) = tokio::task::spawn_blocking(move || db.get_tx(&h)).await {
            return Ok(Json(enrich_tx_detail(&app, &t)));
        }
    }
    let found = app.inner.lock().unwrap().txs.iter().find(|t| t.hash == hash).cloned();
    found.map(|t| Json(enrich_tx_detail(&app, &t))).ok_or(StatusCode::NOT_FOUND)
}

#[derive(serde::Deserialize)]
struct AcctQuery {
    /// scope the account view to a single sequencer (channel id)
    channel: Option<String>,
    before_block: Option<u64>,
    before_hash: Option<String>,
    limit: Option<usize>,
    /// feed filter (shared with /api/txs): visibility, computed-type set, sort.
    kind: Option<String>,
    types: Option<String>,
    sort: Option<String>,
}

/// Account page. Without `?channel`, a cross-sequencer wallet view (which channels
/// it appears in + recent txs everywhere). With `?channel=X`, scoped to that
/// sequencer (txs in X, balance via X's RPC).
async fn api_account(
    State(app): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<AcctQuery>,
) -> Json<Value> {
    let scope = q
        .channel
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|c| resolve_channel(c).ok());

    let after: Option<(u64, String)> = match (q.before_block, q.before_hash.as_deref()) {
        (Some(b), Some(h)) if !h.is_empty() => Some((b, h.to_string())),
        _ => None,
    };
    // transaction history + per-channel breakdown: durable store first.
    let limit = q.limit.unwrap_or(50).min(500);
    let kind = q.kind.as_deref().filter(|k| !k.is_empty() && *k != "all").map(str::to_string);
    let types: Option<Vec<String>> = q
        .types
        .as_deref()
        .map(|s| s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect::<Vec<_>>())
        .filter(|v| !v.is_empty());
    let oldest = q.sort.as_deref() == Some("oldest");
    let mut txs: Vec<TxRecord> = Vec::new();
    let mut total = 0usize;
    let mut channels_raw: Vec<(String, String, usize)> = Vec::new();
    let mut from_db = false;
    if let Some(db) = app.db.clone() {
        let (idc, sc, af, k, ty) =
            (id.clone(), scope.clone(), after.clone(), kind.clone(), types.clone());
        if let Ok(Ok((t, tot, ch))) = tokio::task::spawn_blocking(move || {
            db.account(
                &idc,
                sc.as_deref(),
                af.as_ref().map(|(b, h)| (*b, h.as_str())),
                k.as_deref(),
                ty.as_deref(),
                oldest,
                limit,
            )
        })
        .await
        {
            txs = t;
            total = tot;
            channels_raw = ch;
            from_db = true;
        }
    }

    // L1 (settled) post-state balance: the account's balance as carried in the
    // latest public on-chain leg - the L1-visible view.
    let (l1_balance, home_channel, l1_block) = {
        let dbbal = app.db.as_ref().and_then(|d| d.acct_bal(&id));
        if let Some(b) = dbbal {
            (b.balance.clone(), b.channel.clone(), Some(b.block_id))
        } else {
            let s = app.inner.lock().unwrap();
            let bal = s.accounts.get(&id);
            (
                bal.and_then(|b| b.balance.clone()),
                bal.map(|b| b.channel.clone()).unwrap_or_default(),
                bal.map(|b| b.block_id),
            )
        }
    };

    if !from_db {
        let s = app.inner.lock().unwrap();
        let mut per: BTreeMap<String, (String, usize)> = BTreeMap::new();
        for t in s.txs.iter().filter(|t| t.accounts.iter().any(|a| a == &id)) {
            per.entry(t.channel.clone())
                .or_insert_with(|| (t.channel_short.clone(), 0))
                .1 += 1;
            if scope.as_deref().is_some_and(|c| c != t.channel) {
                continue;
            }
            if kind.as_deref().is_some_and(|k| t.kind != k) {
                continue;
            }
            total += 1;
            if txs.len() < limit {
                txs.push(t.clone());
            }
        }
        channels_raw = per.into_iter().map(|(c, (s, n))| (c, s, n)).collect();
    }
    let channels: Vec<Value> = channels_raw
        .into_iter()
        .map(|(ch, short, n)| json!({"channel": ch, "channel_short": short, "tx_count": n}))
        .collect();

    // L2 (sequencer) balance: exact + nonce from the sequencer's RPC for the
    // relevant channel.
    let balance_channel = scope.clone().unwrap_or(home_channel.clone());
    let rpc_url = {
        let cfg = app.config.lock().unwrap();
        cfg.sequencers
            .iter()
            .find(|sc| {
                !sc.rpc_url.trim().is_empty()
                    && resolve_channel(&sc.channel_id).ok().as_deref()
                        == Some(balance_channel.as_str())
            })
            .map(|sc| sc.rpc_url.trim().to_string())
    };
    let mut l2_balance: Option<String> = None;
    let mut nonce: Option<u64> = None;
    // skip the (slow, Tor) balance RPC on cursor pages - only the first page needs it.
    if after.is_none() {
        if let Some(url) = &rpc_url {
            let client = app.client.lock().unwrap().clone();
            if let Some(client) = client {
                if let Some((b, n)) = rpc_get_account(&client, url, &id).await {
                    l2_balance = Some(b);
                    nonce = Some(n);
                }
            }
        }
    }

    Json(json!({
        "id": id,
        "scope": scope,
        "channel": balance_channel,
        "l2_balance": l2_balance,
        "l1_balance": l1_balance,
        "l1_balance_block": l1_block,
        "nonce": nonce,
        "sequencer_rpc": rpc_url.is_some(),
        "tx_count": total,
        "txs": txs,
        "channels": channels,
    }))
}

/// Download the deployed guest ELF for a ProgramDeployment tx (by tx hash).
async fn api_elf(State(app): State<AppState>, Path(hash): Path<String>) -> Response {
    let bytes = match app.db.clone() {
        Some(db) => {
            let h = hash.clone();
            tokio::task::spawn_blocking(move || db.get_elf(&h)).await.ok().flatten()
        }
        None => None,
    };
    match bytes {
        Some(b) => (
            [
                (axum::http::header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}.elf\"", &hash[..hash.len().min(16)]),
                ),
            ],
            b,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "no ELF stored for this tx").into_response(),
    }
}

/// On-demand: re-resolve shield vs deshield across stored privacy txs (balance delta).
async fn api_relabel(State(app): State<AppState>) -> Json<Value> {
    let Some(db) = app.db.clone() else {
        return Json(json!({"ok": false, "error": "no store"}));
    };
    match tokio::task::spawn_blocking(move || db.relabel_privacy()).await {
        Ok(Ok(n)) => Json(json!({"ok": true, "relabeled": n})),
        _ => Json(json!({"ok": false})),
    }
}

#[derive(serde::Deserialize)]
struct RescanQuery {
    from: u64,
    to: u64,
}

/// Targeted re-scan of an L1 slot range - decode + persist every block in `[from,to]`,
/// capturing deployment ELFs and backfilling fields added after a tx was first stored.
async fn api_rescan(State(app): State<AppState>, Query(q): Query<RescanQuery>) -> Json<Value> {
    let cfg = app.config.lock().unwrap().clone();
    if !cfg.is_configured() {
        return Json(json!({"ok": false, "error": "not configured"}));
    }
    if cfg.sequencer_mode() {
        return Json(json!({"ok": false, "error": "rescan applies to L1 mode only"}));
    }
    // bound the work (token-gated, but cap the range as defense-in-depth)
    const MAX_RESCAN_SLOTS: u64 = 2_000_000;
    let (from, to) = (q.from.min(q.to), q.from.max(q.to));
    if to.saturating_sub(from) > MAX_RESCAN_SLOTS {
        return Json(json!({"ok": false, "error": "range too large (max 2,000,000 slots)"}));
    }
    let base = cfg.base();
    let channel_ids = cfg.channel_ids();
    let focus: Option<BTreeSet<String>> =
        (!channel_ids.is_empty()).then(|| channel_ids.into_iter().collect());
    let client = match app.client.lock().unwrap().clone() {
        Some(c) => c,
        None => return Json(json!({"ok": false, "error": "no client"})),
    };
    let generation = app.generation.load(Ordering::SeqCst);
    let app2 = app.clone();
    tokio::spawn(async move {
        eprintln!("rescan: slots {to}..{from} (targeted)");
        let mut acc = WalkAcc::default();
        backfill_walk(
            &client, &base, &app2, &focus, &BTreeSet::new(), generation, to, from, false, None,
            &mut acc,
        )
        .await;
        eprintln!("rescan: slots {to}..{from} done");
    });
    Json(json!({"ok": true, "rescanning": {"from": from, "to": to}}))
}

#[derive(serde::Deserialize)]
struct DiscoverQuery {
    /// total cap on auto-discovered sequencers (defaults to config.discover_limit or 10)
    limit: Option<usize>,
}

/// Discover rc4-compatible sequencers live on the L1 and start tracking up to `limit`
/// of them. Spawned (the unfiltered window scan can be slow); the newly tracked
/// sequencers appear in /api/state as they're added.
async fn api_discover(State(app): State<AppState>, Query(q): Query<DiscoverQuery>) -> Json<Value> {
    let cap = q
        .limit
        .or(app.config.lock().unwrap().discover_limit)
        .unwrap_or(10);
    let app2 = app.clone();
    tokio::spawn(async move {
        match discover_compatible(&app2, cap).await {
            Ok(f) => println!("discover: scan done, added {} ({:?})", f.len(), f),
            Err(e) => eprintln!("discover: {e:#}"),
        }
    });
    Json(json!({"ok": true, "started": true, "cap": cap}))
}

#[derive(serde::Deserialize)]
struct ProgQuery {
    /// scope the program view to a single sequencer (channel id)
    channel: Option<String>,
}

/// Program page: the transactions invoking a given program (by label/id) within a
/// sequencer, plus the total count. Reached at `/zone/:channel/program/:program_id`.
async fn api_program(
    State(app): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ProgQuery>,
) -> Json<Value> {
    let channel = q
        .channel
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|c| resolve_channel(c).ok());
    let limit = 200usize;

    let mut txs: Vec<TxRecord> = Vec::new();
    let mut total = 0usize;
    let mut from_db = false;
    // durable store first (full history), scoped to the channel.
    if let (Some(db), Some(ch)) = (app.db.clone(), channel.clone()) {
        let (idc, lbl) = (ch, id.clone());
        if let Ok(Ok((t, tot))) =
            tokio::task::spawn_blocking(move || db.program(&idc, &lbl, limit)).await
        {
            txs = t;
            total = tot;
            from_db = true;
        }
    }
    if !from_db {
        let s = app.inner.lock().unwrap();
        for t in s.txs.iter().filter(|t| {
            t.program.as_deref() == Some(id.as_str())
                && channel.as_deref().is_none_or(|c| c == t.channel)
        }) {
            total += 1;
            if txs.len() < limit {
                txs.push(t.clone());
            }
        }
    }

    // A best-guess name for an unrecognized program: prefer the standing classification, else
    // classify on the spot from the txs we just fetched (so a program page resolves even before
    // the periodic pass runs). Never guess for a program a registry already names.
    let known = program_name_map(&app).contains_key(&id);
    let guess = if known || !is_raw_program_id(&id) {
        None
    } else {
        program_guess(&app, &id).or_else(|| {
            let ss: Vec<classify::Sample> = txs
                .iter()
                .filter(|t| t.kind == "public")
                .map(|t| {
                    classify::Sample::new(
                        classify::Kind::from_str(&t.kind),
                        t.accounts.len() as u16,
                        t.instruction_data.clone(),
                    )
                })
                .collect();
            let names = program_name_map(&app);
            let sample_pairs: Vec<(String, Vec<classify::Sample>)> = vec![(id.clone(), ss.clone())];
            let refs = build_reference_profiles(&sample_pairs, &names);
            classify::classify(&ss, &refs)
        })
    };

    Json(json!({
        "id": id,
        "channel": channel,
        "tx_count": total,
        "txs": txs,
        "guess": guess,
    }))
}

/// The configured (SOCKS) client + a channel's sequencer RPC url, if it has one.
fn rpc_for_channel(app: &AppState, channel: &str) -> Option<(Client, String)> {
    let client = app.client.lock().unwrap().clone()?;
    let cfg = app.config.lock().unwrap();
    let url = cfg
        .sequencers
        .iter()
        .find(|sc| {
            !sc.rpc_url.trim().is_empty()
                && resolve_channel(&sc.channel_id).ok().as_deref() == Some(channel)
        })
        .map(|sc| sc.rpc_url.trim().to_string())?;
    Some((client, url))
}

/// Resolve a token **holding** account to its token (definition id, name, supply) via
/// two `getAccount` hops: holding → `TokenHolding.definition_id` → `TokenDefinition`.
async fn resolve_token_of(app: &AppState, account: &str, channel: &str) -> Option<Value> {
    // Offline first: from the on-chain mappings learned at ingest (no sequencer RPC), so
    // token names resolve even while the sequencer is down.
    if let Some(db) = app.db.as_ref() {
        if let Some((definition, name, supply)) = db.resolve_token(account) {
            if !name.is_empty() {
                return Some(json!({
                    "resolved": true,
                    "definition": definition,
                    "name": name,
                    "kind": "fungible",
                    "supply": supply,
                    "holding_balance": "",
                }));
            }
        }
    }
    // Fallback: the sequencer RPC (holding -> definition -> name), cached durably so the
    // next lookup is offline.
    let ch = resolve_channel(channel).ok()?;
    let (client, url) = rpc_for_channel(app, &ch)?;
    let hdata = rpc_get_account_data(&client, &url, account).await?;
    let (definition, balance, _hkind) = parse_token_holding(&hdata)?;
    let (name, kind, supply) = match rpc_get_account_data(&client, &url, &definition).await {
        Some(d) => parse_token_definition(&d).unwrap_or((String::new(), "fungible", 0)),
        None => (String::new(), "fungible", 0),
    };
    if let Some(db) = app.db.as_ref() {
        let _ = db.learn_token(account, &definition, &name, &supply.to_string());
    }
    Some(json!({
        "resolved": true,
        "definition": definition,
        "name": name,
        "kind": kind,
        "supply": supply.to_string(),
        "holding_balance": balance.to_string(),
    }))
}

#[derive(serde::Deserialize)]
struct TokenOfQuery {
    account: String,
    channel: String,
}

/// Resolve which token a holding account belongs to (for token transfers). Cached.
async fn api_token_of(State(app): State<AppState>, Query(q): Query<TokenOfQuery>) -> Json<Value> {
    let account = q.account.trim().to_string();
    if account.is_empty() {
        return Json(json!({"resolved": false}));
    }
    if let Some(v) = app.token_cache.lock().unwrap().get(&account).cloned() {
        return Json(v);
    }
    match resolve_token_of(&app, &account, q.channel.trim()).await {
        Some(v) => {
            app.token_cache.lock().unwrap().insert(account, v.clone());
            Json(v)
        }
        None => Json(json!({"resolved": false})),
    }
}

#[derive(serde::Deserialize)]
struct TokenPageQuery {
    channel: Option<String>,
    before_block: Option<u64>,
    before_hash: Option<String>,
    limit: Option<usize>,
    /// feed filter (shared with /api/txs): visibility, computed-type set, sort.
    kind: Option<String>,
    types: Option<String>,
    sort: Option<String>,
}

/// Token page: a token definition account's metadata (name/kind/supply via the
/// sequencer RPC) + the transactions that touch the definition account.
async fn api_token(
    State(app): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<TokenPageQuery>,
) -> Json<Value> {
    let channel = q
        .channel
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|c| resolve_channel(c).ok());

    let after: Option<(u64, String)> = match (q.before_block, q.before_hash.as_deref()) {
        (Some(b), Some(h)) if !h.is_empty() => Some((b, h.to_string())),
        _ => None,
    };
    let limit = q.limit.unwrap_or(50).min(500);
    let vis = q.kind.as_deref().filter(|k| !k.is_empty() && *k != "all").map(str::to_string);
    let ftypes: Option<Vec<String>> = q
        .types
        .as_deref()
        .map(|s| s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect::<Vec<_>>())
        .filter(|v| !v.is_empty());
    let oldest = q.sort.as_deref() == Some("oldest");

    let (mut name, mut kind, mut supply) = (String::new(), "fungible".to_string(), String::new());
    // metadata RPC only on the first page (cursor pages just append txs).
    if after.is_none() {
        if let Some(ch) = channel.clone() {
            if let Some((client, url)) = rpc_for_channel(&app, &ch) {
                if let Some(d) = rpc_get_account_data(&client, &url, &id).await {
                    if let Some((n, k, s)) = parse_token_definition(&d) {
                        name = n;
                        kind = k.to_string();
                        supply = s.to_string();
                    }
                }
            }
        }
    }

    let mut txs: Vec<TxRecord> = Vec::new();
    let mut total = 0usize;
    if let Some(db) = app.db.clone() {
        let (idc, sc, af, vk, ty) =
            (id.clone(), channel.clone(), after.clone(), vis.clone(), ftypes.clone());
        if let Ok(Ok((t, tot, _ch))) = tokio::task::spawn_blocking(move || {
            db.account(
                &idc,
                sc.as_deref(),
                af.as_ref().map(|(b, h)| (*b, h.as_str())),
                vk.as_deref(),
                ty.as_deref(),
                oldest,
                limit,
            )
        })
        .await
        {
            txs = t;
            total = tot;
        }
    }

    Json(json!({
        "id": id, "channel": channel, "name": name, "kind": kind,
        "supply": supply, "tx_count": total, "txs": txs,
    }))
}

/// Base58 (Bitcoin alphabet) encode - account ids are base58 of their 32 bytes.
fn b58encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::new();
    for &b in bytes {
        if b == 0 {
            out.push('1');
        } else {
            break;
        }
    }
    for &d in digits.iter().rev() {
        out.push(ALPHA[d as usize] as char);
    }
    out
}

/// Parse a token **holding** account's `data` (`TokenHolding`, borsh):
/// `[tag:u8][definition_id:32B][balance u128:16B]`. Returns (definition_id b58, balance, kind).
fn parse_token_holding(data: &[u8]) -> Option<(String, u128, &'static str)> {
    if data.len() < 33 {
        return None;
    }
    let kind = match data[0] {
        0 => "fungible",
        1 => "nft-master",
        2 => "nft-copy",
        _ => return None,
    };
    let definition = b58encode(&data[1..33]);
    let balance = data
        .get(33..49)
        .map(|b| u128::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0);
    Some((definition, balance, kind))
}

/// Parse a token **definition** account's `data` (`TokenDefinition`, borsh):
/// `[tag:u8][name: u32 len + utf8][total_supply u128]…`. Returns (name, kind, supply).
fn parse_token_definition(data: &[u8]) -> Option<(String, &'static str, u128)> {
    if data.len() < 5 {
        return None;
    }
    let kind = match data[0] {
        0 => "fungible",
        1 => "non-fungible",
        _ => return None,
    };
    let nlen = u32::from_le_bytes(data[1..5].try_into().ok()?) as usize;
    let name = String::from_utf8_lossy(data.get(5..5 + nlen)?).to_string();
    let supply = data
        .get(5 + nlen..5 + nlen + 16)
        .map(|b| u128::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0);
    Some((name, kind, supply))
}

/// Query `getAccount` and return the raw `data` byte vector (the program-specific
/// borsh-serialized account state), used to decode token holding/definition state.
async fn rpc_get_account_data(client: &Client, url: &str, account_id: &str) -> Option<Vec<u8>> {
    let body = json!({"jsonrpc":"2.0","method":"getAccount","params":[account_id],"id":1});
    let resp = client.post(url).json(&body).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    let arr = v.get("result")?.get("data")?.as_array()?;
    Some(arr.iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect())
}

/// Query a sequencer's JSON-RPC `getAccount` for an exact balance + nonce.
async fn rpc_get_account(client: &Client, url: &str, account_id: &str) -> Option<(String, u64)> {
    let body = json!({"jsonrpc":"2.0","method":"getAccount","params":[account_id],"id":1});
    let resp = client.post(url).json(&body).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    let result = v.get("result")?;
    let balance = match result.get("balance")? {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let nonce = result.get("nonce").and_then(Value::as_u64).unwrap_or(0);
    Some((balance, nonce))
}

async fn sse_handler(
    State(app): State<AppState>,
) -> Sse<impl futures::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = app.tx.subscribe();
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx)
        .filter_map(|r| async move { r.ok() })
        .map(|msg| Ok(Event::default().data(msg)));
    Sse::new(stream).keep_alive(KeepAlive::default())
}

const DASH_HTML: &str = r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>zonescan - LEZ transaction explorer</title>
<meta name="description" content="Live transaction explorer for Logos Execution Zone (LEZ) sequencers - per-sequencer feed, tx detail, accounts, programs and liveness.">
<link rel="icon" type="image/png" href="/logo.png">
<meta name="theme-color" content='#18181b'>
<meta property="og:type" content="website">
<meta property="og:site_name" content="zonescan">
<meta property="og:title" content="zonescan - LEZ transaction explorer">
<meta property="og:description" content="Live dashboard over public on-chain settlement data for Logos Execution Zone (LEZ) sequencers.">
<meta property="og:url" content="{{ORIGIN}}/">
<meta property="og:image" content="{{ORIGIN}}/logo.png">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="zonescan - LEZ transaction explorer">
<meta name="twitter:description" content="Live dashboard over public on-chain settlement data for Logos Execution Zone (LEZ) sequencers.">
<meta name="twitter:image" content="{{ORIGIN}}/logo.png">
<style>
  :root{
    /* black / silver / white */
    --bg:#f4f4f5; --panel:#ffffff; --line:#e6e6e9; --line2:#d4d4da;
    --fg:#18181b; --muted:#6e6e77; --soft:#9b9ba4;
    --link:#27272a; --navy:#18181b; --silver:#c9c9d0;
    --green:#3d8c40; --amber:#9b9ba4; --purple:#52525b; --red:#c0392b;
    --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    --shadow:0 1px 2px rgba(0,0,0,.05),0 1px 3px rgba(0,0,0,.04);
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
    font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
  a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
  .wrap{max-width:1240px;margin:0 auto;padding:0 18px}
  .mono{font-family:var(--mono)} .mut{color:var(--muted)} .nowrap{white-space:nowrap}
  .htag{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:#9a6a00;background:#fff7e6;border:1px solid #ffe2a8;border-radius:4px;padding:1px 5px;margin-right:6px;cursor:help}
  /* best-guess program name (fingerprint classifier): italic + muted, never styled like a
     verified name; the ≈ and tooltip mark it clearly as unverified. */
  .pguess{font-style:italic;color:var(--muted);cursor:help;border-bottom:1px dotted var(--line2)}
  .pguess .amp{font-style:normal;opacity:.7;margin-right:1px}
  .pguess.lo{opacity:.75}

  /* top bar */
  .topbar{background:linear-gradient(180deg,#f1f1f3,#d9d9de);border-bottom:1px solid #c4c4cc;
    box-shadow:inset 0 1px 0 #ffffff,0 2px 8px rgba(20,20,30,.12);position:sticky;top:0;z-index:10}
  .topbar .wrap{display:flex;align-items:center;gap:18px;height:68px}
  .logo{display:flex;align-items:center;gap:11px;font-weight:700;font-size:19px;color:var(--navy);letter-spacing:.2px}
  .logo .mk{width:40px;height:40px;display:block;filter:drop-shadow(0 1px 1px rgba(0,0,0,.20))}
  .logo b{color:var(--fg)}
  .spacer{flex:1}
  .pill{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line2);border-radius:8px;
    padding:6px 11px;font-size:12px;color:var(--muted);background:linear-gradient(180deg,#ffffff,#f1f1f4);
    box-shadow:0 1px 1px rgba(0,0,0,.04),inset 0 1px 0 #fff}
  /* L1 REST API version tag: same pill chrome, but mono + navy so it reads as a
     version label, distinct from the coloured-dot sync pill next to it */
  .vpill{font-family:var(--mono);font-weight:600;color:var(--navy);letter-spacing:.2px}
  /* channel alias: friendly name as the primary label, raw short-hex as the secondary */
  .calias{font-weight:600;color:var(--navy)} .chex{font-family:var(--mono);font-size:11px;color:var(--soft)}
  .node{font-family:var(--mono);font-size:11px;color:var(--soft);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .btn{border:1px solid var(--line2);border-radius:8px;padding:8px 14px;font-size:13px;color:var(--navy);
    background:linear-gradient(180deg,#ffffff,#ededf0);font-weight:600;box-shadow:0 1px 1px rgba(0,0,0,.05),inset 0 1px 0 #fff}
  .btn:hover{border-color:var(--fg);color:var(--fg);text-decoration:none;background:linear-gradient(180deg,#ffffff,#e4e4e8)}
  .dot{width:8px;height:8px;border-radius:50%;display:inline-block}
  .dot.on{background:var(--green)} .dot.off{background:var(--silver)} .dot.dead{background:var(--red)}

  /* search hero */
  .hero{background:radial-gradient(120% 160% at 0% 0%,#3a3a42,#0c0c0e 62%);padding:30px 0 34px;border-bottom:1px solid #000;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.06)}
  .hero h1{color:#fff;font-size:18px;font-weight:600;margin:0 0 12px}
  .hero .sub{color:#b9b9c1;font-weight:400;font-size:13px}
  .searchbar{display:flex;background:#fff;border-radius:11px;box-shadow:0 10px 30px rgba(0,0,0,.32);overflow:hidden;border:1px solid #1a1a1e}
  .searchbar input{flex:1;border:0;outline:0;padding:15px 16px;font:14px var(--mono);color:var(--fg)}
  .searchbar button{border:0;background:linear-gradient(180deg,#3a3a40,#161618);color:#fff;font-weight:600;padding:0 26px;cursor:pointer;font-size:14px;letter-spacing:.2px}
  .searchbar button:hover{background:linear-gradient(180deg,#161618,#000)}

  /* stat cards */
  .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:-22px 0 18px}
  .card{background:linear-gradient(180deg,#ffffff,#f6f6f8);border:1px solid var(--line);border-radius:12px;
    box-shadow:0 1px 2px rgba(0,0,0,.04),0 6px 16px rgba(20,20,30,.05);padding:16px 18px;
    transition:box-shadow .15s ease,transform .15s ease}
  .card:hover{box-shadow:0 2px 4px rgba(0,0,0,.06),0 12px 26px rgba(20,20,30,.10);transform:translateY(-1px)}
  .card .k{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--soft)}
  .card .v{font-size:21px;font-weight:600;font-family:var(--mono);margin-top:3px;color:var(--navy)}
  .card .s{font-size:12px;color:var(--muted);margin-top:3px}

  /* panels */
  .grid{display:grid;grid-template-columns:340px 1fr;gap:16px;padding-bottom:28px}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 2px rgba(0,0,0,.04),0 6px 18px rgba(20,20,30,.05);overflow:hidden}
  .phead{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:14px 16px;background:linear-gradient(180deg,#fafafb,#f2f2f4);border-bottom:1px solid var(--line);font-weight:600;color:var(--navy);font-size:14px}
  .phead .count{font-weight:400;font-size:12px;color:var(--soft);font-family:var(--mono)}

  /* sequencer list */
  #seqs{max-height:74vh;overflow-y:auto}
  .srow{display:flex;align-items:center;gap:10px;padding:11px 16px;border-bottom:1px solid var(--line);cursor:pointer}
  .srow:last-child{border-bottom:0}
  .srow:hover{background:#f7f9fd} .srow.sel{background:#eef4ff}
  .srow .sm{flex:1;min-width:0}
  .srow .sm .a{font-family:var(--mono);color:var(--link);font-size:13px}
  .srow .sm .b{font-size:11px;color:var(--muted);margin-top:1px}
  /* per-zone labeled detail fields (Channel ID / Sequencer version) */
  .srow .sm .zmeta{display:flex;flex-wrap:wrap;gap:1px 14px;margin:2px 0 1px}
  .srow .sm .zf{display:inline-flex;align-items:baseline;gap:5px;font-size:11px}
  .srow .sm .zk{color:var(--soft);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
  .srow .st{font-size:10px;font-weight:700;letter-spacing:.4px;padding:2px 7px;border-radius:6px}
  .st.alive{background:rgba(19,169,123,.12);color:var(--green)} .st.idle{background:#eef0f4;color:var(--soft)}
  .vchk{font-size:11px;margin-left:6px;cursor:help;font-weight:700}
  .vchk.ok{color:var(--green)} .vchk.bad{color:var(--red)}
  .tipwarn{color:var(--red);font-weight:600}

  /* tables */
  .ttbl{width:100%;border-collapse:collapse}
  .ttbl th{font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:var(--soft);text-align:left;
    font-weight:600;padding:10px 16px;border-bottom:1px solid var(--line);background:#fbfcfe}
  .ttbl td{padding:11px 16px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:middle}
  .ttbl tr.txrow{cursor:pointer} .ttbl tr.txrow:hover{background:#f7f9fd}
  .ttbl tr:last-child td{border-bottom:0}
  /* bounded, internally-scrolling feed (so the page itself stays short) */
  .tscroll{max-height:68vh;overflow:auto}
  .tscroll thead th{position:sticky;top:0;z-index:1}
  /* thin, styled scrollbars for the feed + sequencer lists */
  .tscroll,#seqs{scrollbar-width:thin;scrollbar-color:var(--line2) transparent}
  .tscroll::-webkit-scrollbar,#seqs::-webkit-scrollbar{width:7px;height:7px}
  .tscroll::-webkit-scrollbar-track,#seqs::-webkit-scrollbar-track{background:transparent}
  .tscroll::-webkit-scrollbar-thumb,#seqs::-webkit-scrollbar-thumb{background:var(--line2);border-radius:8px;border:2px solid var(--panel)}
  .tscroll::-webkit-scrollbar-thumb:hover,#seqs::-webkit-scrollbar-thumb:hover{background:var(--soft)}
  .loadrow td{color:var(--soft);text-align:center;padding:13px;font-size:12px}
  .loadrow .dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--soft);margin:0 2px;animation:lpulse 1s infinite ease-in-out}
  .loadrow .dot:nth-child(2){animation-delay:.15s} .loadrow .dot:nth-child(3){animation-delay:.3s}
  @keyframes lpulse{0%,80%,100%{opacity:.25}40%{opacity:1}}
  .lnk{color:var(--link);font-family:var(--mono)}
  .badge{display:inline-block;font-size:11px;font-weight:600;padding:3px 9px;border-radius:6px;border:1px solid transparent}
  .b-public{background:#fff;color:#18181b;border-color:#d4d4d8}
  .b-private{background:#000;color:#fff;border-color:#000}
  .b-deploy{background:#ffedd5;color:#c2410c;border-color:#fdba74}
  .b-token{background:#dcfce7;color:#166534;border-color:#bbf7d0}
  /* visibility */
  .b-vis-public{background:#fff;color:#18181b;border-color:#d4d4d8}
  .b-vis-private{background:#000;color:#fff;border-color:#000}
  /* type */
  .b-ty-token{background:#dcfce7;color:#166534;border-color:#bbf7d0}
  .b-ty-authenticated_transfer{background:#e0f2fe;color:#075985;border-color:#bae6fd}
  .b-ty-clock{background:#f4f4f5;color:#71717a;border-color:#e4e4e7}
  .b-ty-shield{background:#ccfbf1;color:#0f766e;border-color:#99f6e4}
  .b-ty-deshield{background:#fef3c7;color:#92400e;border-color:#fde68a}
  .b-ty-private_send{background:#ede9fe;color:#5b21b6;border-color:#ddd6fe}
  .b-ty-ata{background:#e0e7ff;color:#3730a3;border-color:#c7d2fe}
  .b-ty-amm{background:#fae8ff;color:#86198f;border-color:#f5d0fe}
  .b-ty-pinata,.b-ty-pinata_token{background:#ffe4e6;color:#9f1239;border-color:#fecdd3}
  .b-ty-deploy{background:#ffedd5;color:#c2410c;border-color:#fdba74}
  .b-ty-raw{background:#fef9c3;color:#854d0e;border-color:#fde68a}
  .b-ty-other{background:#f1f1f3;color:#52525b;border-color:#e0e0e4}
  /* best-guess Type badge: neutral pill hosting the muted/italic `≈ name` guess span */
  .b-ty-guess{background:#f8fafc;border-color:var(--line2);font-weight:500}
  .badge .pguess{border-bottom:0}
  /* raw (non-block) inscription: a distinct visibility chip + monospaced content blocks */
  .b-vis-raw{background:#fffbeb;color:#854d0e;border-color:#fde68a}
  .rawtext,.rawhex{font-family:var(--mono);font-size:12.5px;line-height:1.5;white-space:pre-wrap;
    word-break:break-word;background:var(--panel2,#f4f4f5);border:1px solid var(--line2);border-radius:7px;
    padding:12px 14px;margin:0;max-height:360px;overflow:auto}
  .rawhex{white-space:pre;word-break:normal}
  /* LEZ build badge */
  .vbadge{display:inline-block;font-size:10px;font-weight:700;padding:1px 6px;border-radius:5px;
    margin-left:6px;vertical-align:middle;letter-spacing:.3px;text-transform:uppercase}
  .v-rc4{background:#dcfce7;color:#166534}
  .v-rc5{background:#e0e7ff;color:#3730a3} .v-rc3{background:#fef3c7;color:#92400e}
  /* L1-finality badge: green "final" > blue "on L1 · finalizing" > grey "pending" */
  .fbadge{display:inline-block;font-size:10px;font-weight:700;padding:1px 6px;border-radius:5px;vertical-align:middle}
  .fbadge.fin{background:rgba(19,169,123,.14);color:var(--green)}
  .fbadge.safe{background:rgba(37,99,235,.12);color:#1d4ed8}
  .fbadge.pend{background:#eef0f3;color:#6b7280}
  .filt{display:flex;gap:6px}
  .kbtn{border:1px solid var(--line2);background:#fff;color:var(--muted);border-radius:7px;padding:5px 11px;font-size:12px;cursor:pointer}
  .kbtn.sel{border-color:var(--fg);color:var(--fg);background:#ececef}
  .filtbar{display:flex;flex-wrap:wrap;align-items:center;gap:8px 18px;padding:11px 16px;border-bottom:1px solid var(--line)}
  .fgrp{display:flex;align-items:center;gap:8px}
  .flbl{font-size:10px;font-weight:700;color:var(--soft);text-transform:uppercase;letter-spacing:.4px}
  .fsel{font-family:inherit;font-size:12.5px;color:var(--fg);background:var(--panel);border:1px solid var(--line2);
    border-radius:7px;padding:6px 10px;cursor:pointer;accent-color:var(--fg)}
  .fsel:hover{border-color:var(--silver)}
  .fsel:focus{outline:none;border-color:var(--fg)}
  .fdrop{position:relative;display:inline-block}
  .fdbtn{position:relative;text-align:left;min-width:104px;padding-right:24px}
  .fdbtn::after{content:'▾';position:absolute;right:9px;top:50%;transform:translateY(-50%);color:var(--soft);font-size:10px}
  .fdmenu{position:absolute;z-index:30;top:calc(100% + 5px);left:0;min-width:160px;background:var(--panel);
    border:1px solid var(--line2);border-radius:9px;box-shadow:var(--shadow);padding:6px;display:none}
  .fdmenu.open{display:block}
  .fdopt{display:flex;align-items:center;gap:9px;padding:6px 9px;font-size:13px;color:var(--fg);border-radius:6px;cursor:pointer;white-space:nowrap}
  .fdopt:hover{background:var(--bg)}
  .fdopt input{accent-color:var(--fg);width:14px;height:14px;margin:0;cursor:pointer}
  .det td{background:#fbfcfe;padding:16px}
  .kv{display:grid;grid-template-columns:150px 1fr;gap:7px 18px;font-size:13px}
  .kv .k{color:var(--soft);font-size:12px}
  .kv .v{font-family:var(--mono);word-break:break-all}
  .chips span{display:inline-block;background:#f2f5fb;border:1px solid var(--line);border-radius:6px;
    padding:2px 8px;margin:2px 5px 2px 0;font-family:var(--mono);font-size:12px}
  .chips a{display:inline-block;background:#f2f5fb;border:1px solid var(--line);border-radius:6px;
    padding:2px 8px;margin:2px 5px 2px 0;font-family:var(--mono);font-size:12px;cursor:pointer}
  .empty{color:var(--soft);padding:42px 16px;text-align:center;font-size:13px}
  .foot{color:var(--soft);font-size:12px;padding:18px 0 30px;text-align:center}
  #sfoot{display:flex;align-items:center;justify-content:center;gap:14px;height:34px;margin-top:20px;
    font-size:11px;color:var(--soft);background:var(--panel);border-top:1px solid var(--line)}
  #sfoot a{color:var(--muted);text-decoration:none;display:inline-flex;align-items:center;gap:4px}
  #sfoot a:hover{color:var(--fg);text-decoration:none}
  #sfoot svg{width:13px;height:13px;display:block}
  #sfoot .npm{display:inline-flex;align-items:center;opacity:.55;cursor:default}
  code{background:#eef1f6;padding:1px 5px;border-radius:4px;font-size:12px;font-family:var(--mono)}

  /* address overlay */
  .overlay{position:fixed;inset:0;background:rgba(20,30,55,.45);z-index:30;display:none;
    justify-content:center;align-items:flex-start;padding:46px 16px;overflow:auto}
  .sheet{background:var(--panel);border-radius:12px;width:min(960px,100%);overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.3)}
  .shead{display:flex;justify-content:space-between;align-items:flex-start;padding:18px 20px;border-bottom:1px solid var(--line)}
  .shead .ttl{font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--soft)}
  .shead .id{font-family:var(--mono);font-size:13px;word-break:break-all;color:var(--navy);margin-top:3px}
  .closebtn{border:1px solid var(--line2);background:#fff;color:var(--muted);border-radius:8px;padding:6px 11px;cursor:pointer;font-size:13px;white-space:nowrap}
  .ovw{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--line);border-bottom:1px solid var(--line)}
  .ovw>div{background:#fff;padding:16px 20px}
  .ovw .k{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--soft)}
  .ovw .v{font-size:20px;font-weight:600;font-family:var(--mono);color:var(--navy);margin-top:4px}
  @media(max-width:820px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}}
</style></head>
<body>
<div class="topbar"><div class="wrap">
  <a class="logo" href="/"><img class="mk" src="/logo.png" alt="zonescan"> <span><b>zone</b>scan</span></a>
  <div class="spacer"></div>
  <span class="pill"><span class="dot off" id="statdot"></span><span id="statmode">connecting…</span></span>
  <span class="pill vpill" id="statver" title="L1 node REST API version" style="display:none"></span>
  <span class="node" id="node" title="L1 node">-</span>
</div></div>

<div class="hero"><div class="wrap">
  <h1>Logos Execution Zone Explorer <span class="sub">:: data, liveness and consistency of Logos L2</span></h1>
  <div class="searchbar">
    <input id="q" placeholder="Search by Txn Hash / Account / Channel" autocomplete="off" spellcheck="false">
    <button id="qbtn">Search</button>
  </div>
</div></div>

<div class="wrap"><div id="view"></div><div class="foot" id="foot">reads only public on-chain settlement data</div></div>

<script>
let state=null;
let PROGS={};   // program_id_hex -> human name (from sequencers' getProgramIds)
let GUESS={};   // program_id_hex -> {name,confidence,score,margin,samples} best-guess (fingerprint)
let SCHEMAS={}; // program_id_hex -> deployer instruction schema (ABI), for typed decode
const $=(id)=>document.getElementById(id);
const num=(n)=> (n==null?'-':Number(n).toLocaleString());
const esc=(s)=> (s==null?'':String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])));
const sh=(s,a=12,b=8)=> !s?'-':(s.length>a+b+1?s.slice(0,a)+'…'+s.slice(-b):s);
// channel display aliases (channel hex -> friendly name), injected from Rust CHANNEL_ALIASES.
const CHAN_ALIAS={{CHANNEL_ALIASES}};
const aliasOf=(ch)=> ch?(CHAN_ALIAS[String(ch).replace(/^0x/,'').toLowerCase()]||null):null;
// render a channel: friendly alias as the primary label + short hex as secondary; falls
// back to the plain short hex when the channel has no alias.
function chanLabel(ch, shortHex){
  const s=esc(shortHex||sh(ch)); const a=aliasOf(ch);
  return a? `<span class="calias">${esc(a)}</span> <span class="chex">${s}</span>` : s;
}
const fmtAge=(u)=>{ if(!u) return '-'; let s=Math.max(0,Math.floor(Date.now()/1000)-u);
  if(s<60) return s+' secs ago'; if(s<3600) return Math.floor(s/60)+' mins ago'; if(s<86400) return Math.floor(s/3600)+' hrs ago'; return Math.floor(s/86400)+' days ago'; };
function ageOf(t){ let ts=t.timestamp||0; if(ts>1e12) ts=Math.floor(ts/1000);
  if(ts>1e9 && ts<2e10) return fmtAge(ts); if(t.seen_unix) return fmtAge(t.seen_unix); return '-'; }
function badge(k){ return `<span class="badge b-${esc(k)}">${esc((k||'').charAt(0).toUpperCase()+(k||'').slice(1))}</span>`; }
// a public tx that calls the token program is tagged "token" (its own color + filter)
// resolve a tx's program to its name, whether stored as a raw id (rc3 -> PROGS) or as
// the name itself (rc4 decode stores e.g. "token"/"clock" directly).
function progName(p){ return (p&&PROGS[p])||p; }
function txKind(t){ return (t.kind==='public' && progName(t.program)==='token') ? 'token' : t.kind; }
function cap(s){ s=s||''; return s.charAt(0).toUpperCase()+s.slice(1); }
// Visibility = public vs private (the cryptographic kind); Type = the operation.
function txVis(t){ return t.kind==='raw'?'raw':(t.kind==='private'?'private':'public'); }
function txType(t){
  if(t.kind==='raw') return 'raw';
  if(t.kind==='deploy') return 'deploy';
  if(t.kind==='private'){ const s=t.subtype; return (s==='shield'||s==='deshield')?s:'authenticated_transfer'; }
  return progName(t.program)||'public';
}
const TYPE_LABEL={clock:'Clock',token:'Token',authenticated_transfer:'Transfer',ata:'ATA',amm:'AMM',
  pinata:'Pinata',pinata_token:'Pinata Token',deploy:'Deploy',shield:'Shield',deshield:'Deshield',
  'private-send':'Transfer',public:'Public',private:'Private',raw:'Inscription'};
// known op -> label; an unresolved program id (raw hex) is just "Program" (the id
// itself belongs in the Program field / tooltip, not the Type column).
function typeLabel(ty){ if(TYPE_LABEL[ty]) return TYPE_LABEL[ty]; return /^[0-9a-f]{40,}$/i.test(ty)?'Program':cap(ty); }
function tyClass(ty){ return TYPE_LABEL[ty]?ty.replace(/-/g,'_'):'other'; }
function visBadge(t){ const v=txVis(t);
  if(v==='raw') return `<span class="badge b-vis-raw" title="a raw text/data inscription - not a sequencer block">Raw</span>`;
  return `<span class="badge b-vis-${v}">${v==='private'?'Private':'Public'}</span>`; }
function typeBadge(t){
  // Precedence: a verified program name renders exactly as before; else, for a public tx
  // invoking a program with NO verified name but a fingerprint guess, show `≈ guessname` in the
  // muted/italic guess style (tooltip + confidence); else the raw id / generic kind.
  const g=(t.kind==='public')?guessFor(t.program,t):null;
  if(g) return `<span class="badge b-ty-guess">${guessHtml(g)}</span>`;
  const ty=txType(t); return `<span class="badge b-ty-${tyClass(ty)}" title="${esc(ty)}">${esc(typeLabel(ty))}</span>`; }
// map a filter key to query params (kind / subtype / program_name)
// ---- shared transactions filter: Visibility + multi-select Type + Sort ----
// FLT persists across screens; feeds re-fetch with these as server params, and the
// live stream is gated by filterMatches(). "clock" in the type set re-includes clock txs.
const FLT={vis:'all',types:new Set(),sort:'newest'};
const TYPE_CHIPS=[['authenticated_transfer','Transfer'],['token','Token'],['clock','Clock'],
  ['shield','Shield'],['deshield','Deshield'],['amm','AMM'],['ata','ATA'],['pinata','Pinata'],
  ['program','Program'],['deploy','Deploy'],['raw','Inscription']];
function filterBar(){
  return `<div class="filtbar">
    <span class="fgrp"><span class="flbl">Visibility</span>
      <select id="f_vis" class="fsel"><option value="all">All</option><option value="public">Public</option><option value="private">Private</option><option value="raw">Raw</option></select></span>
    <span class="fgrp"><span class="flbl">Type</span>
      <span class="fdrop">
        <button type="button" class="fsel fdbtn" id="f_types_btn">All types</button>
        <div class="fdmenu" id="f_types_menu">${TYPE_CHIPS.map(([k,l])=>`<label class="fdopt"><input type="checkbox" value="${k}"><span>${esc(l)}</span></label>`).join('')}</div>
      </span></span>
    <span class="fgrp"><span class="flbl">Sort</span>
      <select id="f_sort" class="fsel"><option value="newest">Newest</option><option value="oldest">Oldest</option></select></span>
  </div>`;
}
function wireFilter(reload){
  const vs=$('f_vis'); if(vs){ vs.value=FLT.vis; vs.onchange=()=>{ FLT.vis=vs.value; reload(); }; }
  const sr=$('f_sort'); if(sr){ sr.value=FLT.sort; sr.onchange=()=>{ FLT.sort=sr.value; reload(); }; }
  const tb=$('f_types_btn'), tm=$('f_types_menu');
  if(tb&&tm){
    const upd=()=>{ tb.textContent=FLT.types.size?FLT.types.size+' selected':'All types'; };
    upd();
    tb.onclick=(e)=>{ e.stopPropagation(); tm.classList.toggle('open'); };
    tm.querySelectorAll('input').forEach(cb=>{ cb.checked=FLT.types.has(cb.value);
      cb.onchange=()=>{ if(cb.checked)FLT.types.add(cb.value); else FLT.types.delete(cb.value); upd(); reload(); }; });
  }
  if(!window._fdbound){ window._fdbound=1; document.addEventListener('click',e=>{
    document.querySelectorAll('.fdmenu.open').forEach(m=>{ if(!m.parentElement.contains(e.target)) m.classList.remove('open'); }); }); }
}
function filterParams(p){
  if(FLT.vis!=='all') p.set('kind',FLT.vis);
  if(FLT.types.size) p.set('types',[...FLT.types].join(','));
  if(FLT.sort==='oldest') p.set('sort','oldest');
  return p;
}
// an unresolved raw-hex program id collapses to the generic "program" type for filtering
function typeKey(t){ const ty=txType(t); return /^[0-9a-f]{40,}$/i.test(ty)?'program':ty; }
function filterMatches(t){
  if(FLT.vis==='public' && txVis(t)!=='public') return false;
  if(FLT.vis==='private' && txVis(t)!=='private') return false;
  if(FLT.vis==='raw' && txVis(t)!=='raw') return false;
  if(FLT.types.size && !FLT.types.has(typeKey(t))) return false;
  return true;
}
const u=encodeURIComponent;

// program ids for unknown programs are a 64-hex blob; shorten them (e.g. 625e05…8240c)
// so they don't blow out the table, but keep readable built-in names (token, amm…) whole.
function progShort(p){ if(p&&PROGS[p]) return PROGS[p]; return (p && /^[0-9a-f]{40,}$/i.test(p)) ? sh(p,6,5) : p; }
// a program is "unnamed" when no registry names it (a raw 64-hex id, not a built-in name).
function isRawId(p){ return !!(p && /^[0-9a-f]{40,}$/i.test(p) && !PROGS[p]); }
// best-guess for a program: the per-row hint (from the tx) or the global GUESS map.
function guessFor(p,row){ if(p&&PROGS[p]) return null; return (row&&row.program_guess)||GUESS[p]||null; }
// render a best-guess as `≈ name` - italic/muted, tooltip, NEVER styled like a verified name.
function guessHtml(g){ const pc=Math.round((g.confidence||0)*100);
  const tip=`best-guess from tx fingerprint — unverified · ${pc}% confidence`+(g.samples?` · ${g.samples} tx${g.samples===1?'':'s'}`:'');
  const lo=(g.confidence||0)<0.6?' lo':'';
  return `<span class="pguess${lo}" title="${esc(tip)}"><span class="amp">≈</span> ${esc(g.name)}</span>`; }
function progCell(t){ if(!t.program) return '-';
  const g=guessFor(t.program,t);
  const inner=g?guessHtml(g):esc(progShort(t.program));
  return `<a class="lnk nowrap" href="/zone/${u(t.channel)}/program/${u(t.program)}" title="${esc(t.program)}">${inner}</a>`; }
// risc0 serializes u128 as 4 little-endian u32 words
function u128le(w,off){ let v=0n; for(let i=0;i<4;i++){ v += BigInt((w[off+i]||0)>>>0) << BigInt(32*i); } return v; }
// decode a public tx's instruction. token Transfer (variant 0) = [0,<u128 amount>] with
// accounts [sender, recipient]; other programs show the raw words.
function u64le(w,off){ return BigInt((w[off]||0)>>>0) | (BigInt((w[off+1]||0)>>>0)<<32n); }
// risc0 String = [len:u32][ceil(len/4) words of utf8, little-endian packed per word]
function r0str(w,off){ const len=(w[off]||0)>>>0,nw=Math.ceil(len/4); let b=[]; for(let i=0;i<nw;i++){ const x=(w[off+1+i]||0)>>>0; for(let k=0;k<4;k++) b.push((x>>>(8*k))&0xff); } try{ return new TextDecoder().decode(new Uint8Array(b.slice(0,len))); }catch(e){ return ''; } }
function r0strWords(w,off){ return 1+Math.ceil(((w[off]||0)>>>0)/4); } // words a String consumes
// ---- deployer-schema (ABI) decoder: walk risc0 words by a type descriptor ----
// type t: "u8"/"u16"/"u32"/"bool" (1 word) · "u64"(2) · "u128"(4) · "string" (len+packed)
// · "bytes" (len + 1 word/byte) · {vec:T} · {array:[T,N]} · {struct:[{name,type}]}
// · {enum:[{name,fields:[{name,type}]}]}. Returns {v, p} (value + next word index).
function r0dec(w,t,p){
  if(typeof t==='string'){
    if(t==='u8'||t==='u16'||t==='u32') return {v:(w[p]||0)>>>0, p:p+1};
    if(t==='bool') return {v:!!w[p], p:p+1};
    if(t==='u64') return {v:u64le(w,p).toString(), p:p+2};
    if(t==='u128') return {v:u128le(w,p).toString(), p:p+4};
    if(t==='string') return {v:r0str(w,p), p:p+r0strWords(w,p)};
    if(t==='bytes'){ const n=(w[p]||0)>>>0, b=w.slice(p+1,p+1+n); return {v:bytesDisp(b), p:p+1+n}; }
    return {v:'?'+t, p:p+1};
  }
  if(t&&t.vec){ const n=(w[p]||0)>>>0; let q=p+1; const a=[]; for(let i=0;i<n&&q<=w.length;i++){ const r=r0dec(w,t.vec,q); a.push(r.v); q=r.p; } return {v:a, p:q}; }
  if(t&&t.array){ const et=t.array[0],n=t.array[1]|0; let q=p; const a=[]; for(let i=0;i<n;i++){ const r=r0dec(w,et,q); a.push(r.v); q=r.p; } return {v:a, p:q}; }
  if(t&&t.struct){ let q=p; const o={}; for(const f of t.struct){ const r=r0dec(w,f.type,q); o[f.name]=r.v; q=r.p; } return {v:o, p:q}; }
  if(t&&t.enum){ const vi=(w[p]||0)>>>0, vd=t.enum[vi]; let q=p+1; if(!vd) return {v:'variant '+vi, p:q}; const o={_variant:vd.name}; for(const f of (vd.fields||[])){ const r=r0dec(w,f.type,q); o[f.name]=r.v; q=r.p; } return {v:o, p:q}; }
  return {v:null, p:p+1};
}
function bytesDisp(b){ return (b.length&&b.every(x=>x>=9&&x<=126)) ? b.map(x=>String.fromCharCode(x)).join('') : '0x'+b.map(x=>((x>>>0)&0xff).toString(16).padStart(2,'0')).join(''); }
function fmtSchema(v){
  if(v===null||v===undefined) return '';
  if(Array.isArray(v)) return '['+v.map(fmtSchema).join(', ')+']';
  if(typeof v==='object'){ const head=v._variant?'<b>'+esc(v._variant)+'</b>':''; const ps=[];
    for(const k in v){ if(k==='_variant') continue; ps.push('<span class="mut">'+esc(k)+':</span> '+fmtSchema(v[k])); }
    return head+(ps.length?(head?' {':'{')+' '+ps.join(', ')+' }':''); }
  return '<b>'+esc(String(v))+'</b>';
}
function decodeBySchema(w,schema){ try{ return fmtSchema(r0dec(w,schema,0).v); }catch(e){ return null; } }
// `tok` (optional) = resolved /api/token_of for the holding account (token standard).
function instrText(t,tok){
  const w=t.instruction_data||[]; if(!w.length) return '';
  // deployer-supplied schema (ABI) for a custom program decodes it into typed fields
  if(t.program && SCHEMAS[t.program]){ const d=decodeBySchema(w, SCHEMAS[t.program]); if(d) return d; }
  const name=PROGS[t.program]||t.program, a=t.accounts||[];
  const acc=(i)=>a[i]?`<a class="lnk" href="/zone/${u(t.channel)}/wallet/${u(a[i])}">${esc(sh(a[i],6,4))}</a>`:'';
  const ft=(i)=>(a[0]?` · from ${acc(0)}`:'')+(a[1]?` → to ${acc(1)}`:'');
  // token-standard Instruction (risc0 enum): 0 Transfer, 1 NewFungibleDefinition,
  // 2 NewDefinitionWithMetadata, 3 InitializeAccount, 4 Burn, 5 Mint, 6 PrintNft
  if(name==='token' && w.length>=1){
    const v=w[0]>>>0;
    const tn=['Transfer','NewFungibleDefinition','NewDefinitionWithMetadata','InitializeAccount','Burn','Mint','PrintNft'][v];
    if(v===0 && w.length>=5){ // Transfer{amount: u128}
      let tk='token-standard';
      if(tok&&tok.resolved&&tok.definition){ const lbl=tok.name||sh(tok.definition,6,4);
        tk=`<a class="lnk" href="/zone/${u(t.channel)}/token/${u(tok.definition)}">${esc(lbl)}</a>`; }
      return `<b>Transfer</b> <b>${u128le(w,1).toString()}</b> ${tk}`+ft();
    }
    if(v===1){ // NewFungibleDefinition{name: String, total_supply: u128}
      const nm=r0str(w,1), sup=u128le(w,1+r0strWords(w,1));
      return `<b>NewFungibleDefinition</b> - <b>${esc(nm)}</b> · supply ${sup.toString()}`;
    }
    if(v===3) return `<b>InitializeAccount</b>`;
    return `<b>${esc(tn||('variant '+v))}</b> <span class="mono mut" style="font-size:11px;word-break:break-all">[${w.slice(1,17).join(', ')}${w.length>17?', …':''}]</span>`;
  }
  // native LEZ (authenticated_transfer Instruction = u128 balance_to_move, 4 words)
  if(name==='authenticated_transfer' && w.length>=4){
    const amt=u128le(w,0);
    if(amt===0n) return `<b>Register</b> - initialize native account`+(a[0]?` · ${acc(0)}`:'');
    return `<b>Transfer</b> <b>${amt.toString()}</b> <b>LEZ</b> <span class="mut" style="font-size:11px">(native)</span>`+ft();
  }
  // clock tick = u64 block timestamp (ms)
  if(name==='clock' && w.length>=2){
    const ts=u64le(w,0); let d=''; try{ const ms=Number(ts); if(ms>1e12&&ms<4e12) d=' ('+new Date(ms).toISOString().replace('T',' ').slice(0,19)+'Z)'; }catch(e){}
    return `<b>Tick</b> - timestamp ${ts.toString()}${d}`;
  }
  // pinata Instruction = u128 PoW solution
  if(name==='pinata' && w.length>=4) return `<b>Claim</b> - PoW solution ${u128le(w,0).toString()}`;
  // amm enum: 0 NewDefinition, 1 AddLiquidity, 2 RemoveLiquidity (u128 fields)
  if(name==='amm' && w.length>=1){
    const vn=['NewDefinition','AddLiquidity','RemoveLiquidity'][w[0]>>>0]||('variant '+(w[0]>>>0));
    return `<b>${esc(vn)}</b> <span class="mono mut" style="font-size:11px;word-break:break-all">[${w.slice(1,17).join(', ')}${w.length>17?', …':''}]</span>`;
  }
  // ATA (associated token account) enum: 0 Create{program_id}, 1 Transfer{program_id,u128},
  // 2 Burn{program_id,u128}. program_id is 8 u32 words, so amount (u128, 4 words) is at w[9].
  if(name==='ata' && w.length>=1){
    const v=w[0]>>>0;
    if(v===0) return `<b>Create</b> - associated token account`+ft();
    if(v===1 && w.length>=13) return `<b>Transfer</b> <b>${u128le(w,9).toString()}</b> <span class="mut">via ATA</span>`+ft();
    if(v===2 && w.length>=13) return `<b>Burn</b> <b>${u128le(w,9).toString()}</b> <span class="mut">via ATA</span>`+ft();
    return `<b>${['Create','Transfer','Burn'][v]||('variant '+v)}</b> <span class="mono mut" style="font-size:11px;word-break:break-all">[${w.slice(1,17).join(', ')}${w.length>17?', …':''}]</span>`;
  }
  // ---- no registered schema: a best-effort, clearly-TENTATIVE decode ----
  // risc0 words aren't self-describing, so these are guesses (a registered schema is
  // the exact path). We recognize the common shapes; everything carries a "tentative" tag.
  const raw=`<span class="mono" style="font-size:11px;word-break:break-all">[${w.slice(0,20).join(', ')}${w.length>20?', …':''}]</span>`;
  const tag='<span class="htag" title="best-effort guess - no instruction schema is registered for this program; add one to decode exactly">tentative</span>';
  // (a) a length-prefixed printable-ASCII string (e.g. a deployed demo’s text input)
  const str=asAsciiInstr(w);
  if(str) return `${tag}<b>&ldquo;${esc(str)}&rdquo;</b> <span class="mut" style="font-size:11px">· string · ${w.length} words</span>`;
  // (b) a u64 (lo,hi word pair) that reads as a plausible ms-epoch timestamp (clocks, deadlines…)
  for(let i=0;i+1<w.length;i++){
    const v=BigInt(w[i]>>>0)+(BigInt(w[i+1]>>>0)<<32n);
    if(v>=1500000000000n && v<=2500000000000n){
      let d=v.toString(); try{ d=new Date(Number(v)).toISOString().replace('T',' ').slice(0,19)+'Z'; }catch(e){}
      const bt=(t.timestamp&&v===BigInt(t.timestamp))?' <span class="mut">· = block time</span>':'';
      const pos=i?` <span class="mut">(words ${i}-${i+1})</span>`:'';
      return `${tag}<b>u64</b> ${esc(d)} <span class="mut">timestamp</span>${bt}${pos} ${raw}`;
    }
  }
  // (c) otherwise: show the raw risc0 instruction words - this IS the decoded structure
  // (risc0 words aren't self-describing); a registered schema would name the fields. Lead
  // with a likely enum-variant tag so an unnamed program still reads as decoded, not blank.
  const v0=w.length?`<b>variant ${w[0]>>>0}</b> · `:'';
  return `${v0}<span class="mut">${w.length} u32 word${w.length===1?'':'s'} · no schema</span> ${raw}`;
}
// recognize a (length-prefixed) printable-ASCII byte string in raw instruction words -
// the common shape for simple custom-program inputs (e.g. a deployed "Hola mundo!" demo).
function asAsciiInstr(w){
  if(!w||!w.length) return null;
  let b=w;
  if(w.length>1 && w[0]===w.length-1) b=w.slice(1); // strip a leading byte count
  if(!b.length || b.length>512) return null;
  if(!b.every(x=>(x>=32&&x<=126)||x===9||x===10||x===13)) return null;
  const s=b.map(x=>String.fromCharCode(x)).join('');
  return s.trim().length>=2 ? s : null;
}

// ---- corpus structural inference: a tentative field layout for a custom program ----
// Group its instructions by leading variant tag; across the corpus, mark each byte
// position constant vs varying (and high-entropy 32-byte runs as ids); then read THIS
// tx by that inferred layout. A registered schema is still the exact path.
const LAYOUTS={};
function b58(bytes){
  const A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n=0n; for(const x of bytes) n=n*256n+BigInt(x>>>0);
  let s=''; while(n>0n){ s=A[Number(n%58n)]+s; n/=58n; }
  for(const x of bytes){ if((x>>>0)===0) s='1'+s; else break; }
  return s||'1';
}
function leInt(w,off,len){ let n=0n; for(let k=0;k<len;k++) n+=BigInt(w[off+k]>>>0)<<(8n*BigInt(k)); return n; }
function hexOf(w,off,len){ return w.slice(off,off+len).map(x=>(x>>>0).toString(16).padStart(2,'0')).join(''); }
function inferLayout(samples){
  samples=(samples||[]).filter(w=>w&&w.length&&w.every(x=>(x>>>0)<=255)); // byte-serialized instructions only
  if(samples.length<6) return null;
  const byV={}; for(const w of samples){ const v=w[0]>>>0; (byV[v]=byV[v]||[]).push(w); }
  const variants={};
  for(const vk in byV){
    const g=byV[vk], lc={}; g.forEach(w=>lc[w.length]=(lc[w.length]||0)+1);
    const len=+Object.keys(lc).sort((a,b)=>lc[b]-lc[a])[0];
    const gg=g.filter(w=>w.length===len); if(gg.length<5||len<2||len>1024) continue;
    const cst=[], hi=[];
    for(let p=0;p<len;p++){ const s=new Set(gg.map(w=>w[p]>>>0)); cst.push(s.size===1?[...s][0]:null); hi.push(s.size>=8); }
    const fields=[{kind:'tag',off:0,len:1}]; let i=1;
    while(i<len){
      if(cst[i]!==null){ let j=i; while(j<len&&cst[j]!==null) j++; fields.push({kind:'fixed',off:i,len:j-i}); i=j; continue; }
      let j=i; while(j<len&&cst[j]===null) j++;
      let bS=-1,bL=0,cs=0; for(let k=i;k<=j;k++){ if(k<j&&hi[k]) cs++; else { if(cs>bL){bL=cs;bS=k-cs;} cs=0; } }
      if(bL>=32){ const idL=bL>=64?64:32;
        if(bS>i) fields.push({kind:(bS-i)<=4?'u32':(bS-i)<=8?'u64':(bS-i)<=16?'u128':'bytes',off:i,len:bS-i});
        fields.push({kind:'id'+idL,off:bS,len:idL});
        const tS=bS+idL; if(tS<j) fields.push({kind:(j-tS)<=8?'u64':'bytes',off:tS,len:j-tS});
      } else { const L=j-i; fields.push({kind:L===4?'u32':L===8?'u64':L===16?'u128':'bytes',off:i,len:L}); }
      i=j;
    }
    variants[vk]={samples:gg.length,len,fields};
  }
  return Object.keys(variants).length?{variants}:null;
}
async function ensureLayout(program,channel){
  if(program in LAYOUTS) return LAYOUTS[program];
  LAYOUTS[program]=null;
  try{ const d=await (await fetch('/api/program/'+u(program)+'?channel='+u(channel))).json();
    LAYOUTS[program]=inferLayout((d.txs||[]).map(t=>t.instruction_data)); }catch(e){}
  return LAYOUTS[program];
}
function renderByLayout(w,layout,t){
  const v=w.length?(w[0]>>>0):-1, vl=layout&&layout.variants[v];
  if(!vl || w.length!==vl.len) return null;
  const acc=new Set(t.accounts||[]);
  const parts=vl.fields.map(f=>{
    if(f.kind==='tag') return `<b>variant ${v}</b>`;
    if(f.kind==='fixed') return `<span class="mut" title="constant across the corpus · 0x${hexOf(w,f.off,f.len)}">fixed[${f.len}]</span>`;
    if(f.kind==='u32'||f.kind==='u64'||f.kind==='u128') return `<b>${leInt(w,f.off,f.len).toString()}</b> <span class="mut">${f.kind}</span>`;
    if(f.kind==='id32'||f.kind==='id64'){ const id=b58(w.slice(f.off,f.off+f.len)), known=acc.has(id);
      const lbl=known?`<a class="lnk" href="/zone/${u(t.channel)}/wallet/${u(id)}">${esc(sh(id,6,4))}</a>`:esc(sh(id,8,6));
      return `<b>id</b> ${lbl} <span class="mut">${f.len}B${known?' · account':''}</span>`; }
    return `<span class="mut">bytes[${f.len}]</span> <span class="mono" style="font-size:11px">${hexOf(w,f.off,f.len)}</span>`;
  });
  return `<span class="htag" title="layout inferred from this program's instruction corpus - tentative, not a registered schema">inferred</span>${parts.join(' <span class="mut">·</span> ')} <span class="mut" style="font-size:11px">· ${vl.samples} samples</span>`;
}

function verBadge(s){ return s.version?`<span class="vbadge v-${esc(s.version)}" title="LEZ build">${esc(s.version)}</span>`:''; }
// a zone's display title: the friendly alias when known, else the short hex.
function zoneTitle(s){ return aliasOf(s.channel) || s.channel_short || sh(s.channel); }
// sequencer (LEZ/zone) version as a labeled value: the rc-family badge (rc3/rc4/rc5),
// or an em-dash when the zone has no decoded version yet (e.g. a light/no-decode build).
function verValue(s){ return s.version?`<span class="vbadge v-${esc(s.version)}" title="LEZ build">${esc(s.version)}</span>`:'<span class="mut">—</span>'; }
function consBadge(s){
  const c=s.consistency||{};
  const skew=c.checked>0 && c.hash_failures===c.checked; // uniform hash fail = version skew
  const gaps=c.id_gaps||0;
  if(s.consistent===true){
    const notes=[]; if(skew) notes.push('hash recompute n/a (version skew)'); if(gaps) notes.push(gaps+' id-gap'+(gaps>1?'s':''));
    const title='chain links verified over '+(c.checked||0)+' blocks'+(notes.length?' - '+notes.join(', '):'');
    return `<span class="vchk ok" title="${esc(title)}">✓ ${notes.length?'links ok':'verified'}${gaps?' · '+gaps+' gap'+(gaps>1?'s':''):''}</span>`;
  }
  if(s.consistent===false){
    const why=[]; if(c.chain_breaks) why.push(c.chain_breaks+' chain break'+(c.chain_breaks>1?'s':'')); if(c.hash_failures&&!skew) why.push(c.hash_failures+' hash mismatch');
    return `<span class="vchk bad" title="${esc(why.join(', ')||'inconsistent')}">⚠ inconsistent</span>`;
  }
  return '';
}
function chainCheckText(s){
  const c=s.consistency||{};
  if(s.consistent==null) return 'not verified yet';
  const skew=c.checked>0 && c.hash_failures===c.checked;
  if(s.consistent===false){ const why=[]; if(c.chain_breaks) why.push(c.chain_breaks+' chain break(s)'); if(c.hash_failures&&!skew) why.push(c.hash_failures+' hash mismatch(es)'); return 'INCONSISTENT - '+(why.join(', ')||'see details'); }
  let t='links verified over '+(c.checked||0)+' blocks'; const notes=[];
  if(skew) notes.push('hash recompute unavailable - explorer/sequencer common version differ');
  if(c.id_gaps) notes.push(c.id_gaps+' id-gap(s): missed or not-yet-settled block(s)');
  if(notes.length) t+=' ('+notes.join('; ')+')';
  return t;
}
function tipNote(s){
  if(s.seq_tip==null) return '';
  if(s.seq_tip < s.latest_block_id) return ` · <span class="tipwarn" title="sequencer reports a lower tip than it has settled on L1">seq tip #${num(s.seq_tip)} &lt; L1 #${num(s.latest_block_id)} ⚠</span>`;
  return ` · seq tip #${num(s.seq_tip)} (L1 #${num(s.latest_block_id)})`;
}

// tx table rows; links route to per-tx and per-wallet pages (scoped to the tx's sequencer)
// short account id for action sentences
function accShort(a){ return a?esc(sh(a,6,4)):'?'; }
// bigint-safe thousands grouping (amounts are u128 strings, may exceed Number precision)
function grp(s){ return s==null?'':String(s).replace(/\B(?=(\d{3})+(?!\d))/g,','); }
// L1-finality (three tiers) from a tx's block_id vs the sequencer's two thresholds:
//   block_id <= finalized_block_id            -> "final"   (irreversible, past lib_slot)
//   finalized < block_id <= safe_block_id     -> "on L1"   (inscribed, finalizing ~1h)
//   block_id > safe_block_id                  -> "pending" (not yet inscribed / unseen on L1)
function seqFinal(ch){ const q=((state&&state.sequencers)||[]).find(x=>x.channel===ch); return q?(q.finalized_block_id||0):0; }
function seqSafe(ch){ const q=((state&&state.sequencers)||[]).find(x=>x.channel===ch); return q?Math.max(q.safe_block_id||0,q.finalized_block_id||0):0; }
function finalityBadge(t){
  // A raw inscription has no L2 block_id; its finality is its L1 slot vs the last-final slot
  // (it lives directly on the L1). Below lib => final; a freshly-streamed tip => finalizing.
  if(t.kind==='raw'){
    const lib=(state&&state.l1&&state.l1.lib_slot)||0, sl=t.slot||0;
    if(!sl) return '';
    if(lib && sl<=lib) return `<span class="fbadge fin" title="final - the inscription's L1 slot ${num(sl)} is at/below the last-final slot ${num(lib)}">final</span>`;
    return `<span class="fbadge safe" title="inscribed on the L1 (slot ${num(sl)}), finalizing until past the last-final slot ${num(lib)}">on L1 · finalizing</span>`;
  }
  const fin=seqFinal(t.channel), safe=seqSafe(t.channel);
  if(!fin && !safe) return ''; // unknown (light build / no finality info yet)
  if(t.block_id<=fin)
    return `<span class="fbadge fin" title="final - irreversibly settled on the L1 (finalized up to block #${num(fin)})">final</span>`;
  if(t.block_id<=safe)
    return `<span class="fbadge safe" title="inscribed on the L1 and finalizing (irreversible once past the L1's last-final slot, ~1h); finalized up to #${num(fin)}">on L1 · finalizing</span>`;
  return `<span class="fbadge pend" title="pending - not yet observed inscribed on the L1 (on L1 up to #${num(safe)})">pending</span>`;
}
// A human one-line ACTION for a tx: "<verb> <amount> <token> from <a> to <b>", derived from
// the program name + instruction variant + resolved token/amount/accounts. Never blank -
// falls back to "<program> · variant N". rc4 + rc5 (LE program ids resolve via progName).
function txAction(t){
  const w=t.instruction_data||[], a=t.accounts||[], name=progName(t.program), tok=t.token, amt=t.amount;
  const amtS=amt!=null?grp(amt):'';
  const ft=(a[0]?' from '+accShort(a[0]):'')+(a[1]?' to '+accShort(a[1]):'');
  if(t.kind==='raw') return 'Raw inscription'+(t.slot?' · L1 slot '+num(t.slot):'');
  if(t.kind==='deploy') return 'Deploy program'+(t.deploy_program?' '+esc(progShort(t.deploy_program)):'');
  if(t.kind==='private'){ const s=t.subtype; if(s==='shield') return 'Shield (private deposit)'; if(s==='deshield') return 'Deshield (private withdraw)'; return 'Private transfer'; }
  if(name==='ata'){ const v=w[0]>>>0;
    if(v===0) return `Create ${tok?esc(tok)+' ':''}token account${a[0]?' for '+accShort(a[0]):''}`;
    if(v===1) return `Transfer ${amtS?amtS+' ':''}${tok?esc(tok)+' ':''}via ATA${ft}`;
    if(v===2) return `Burn ${amtS?amtS+' ':''}${tok?esc(tok)+' ':''}via ATA`; }
  if(name==='token'){ const v=w[0]>>>0;
    if(v===0) return `Transfer ${amtS?amtS+' ':''}${tok?esc(tok):'tokens'}${ft}`;
    if(v===1) return `Create token ${tok?esc(tok):''}${amtS?' · supply '+amtS:''}`;
    if(v===3) return `Initialize ${tok?esc(tok)+' ':''}token account`;
    if(v===4) return `Burn ${amtS?amtS+' ':''}${tok?esc(tok):'tokens'}`;
    if(v===5) return `Mint ${amtS?amtS+' ':''}${tok?esc(tok):'tokens'}`; }
  if(name==='authenticated_transfer'){
    if(w.length>=4 && u128le(w,0)===0n) return `Register native account${a[0]?' '+accShort(a[0]):''}`;
    const na=w.length>=4?grp(u128le(w,0).toString()):amtS;
    return `Transfer ${na?na+' ':''}LEZ${ft}`; }
  if(name==='pinata') return `Claim native LEZ${a[0]?' to '+accShort(a[0]):''}`;
  if(name==='faucet') return `Faucet dispense ${tok?esc(tok)+' ':''}${a[0]?'to '+accShort(a[0]):''}`.replace(/ +$/,'');
  if(name==='clock') return 'Clock tick';
  const pn=(name&&!/^[0-9a-f]{40,}$/i.test(name))?name.replace(/_/g,' '):progShort(t.program);
  return `${esc(cap(pn||'program'))}${w.length?' · variant '+(w[0]>>>0):''}`;
}
function txRows(list){
  if(!list||!list.length) return '<tr><td colspan="8" class="empty">no transactions</td></tr>';
  return list.map(t=>{
    const z=t.channel;
    const a0=t.accounts&&t.accounts[0];
    const accs=a0?`<a class="lnk" href="/zone/${u(z)}/wallet/${u(a0)}">${esc(sh(a0,6,4))}</a>`+(t.accounts.length>1?` <span class="mut">+${t.accounts.length-1}</span>`:''):'<span class="mut">-</span>';
    // a raw inscription has no L2 block; locate it by its L1 slot instead of a block height.
    const blockCell=t.kind==='raw'?`<span class="mut nowrap" title="L1 slot">L1 ${t.slot?num(t.slot):'—'}</span>`:`#${num(t.block_id)}`;
    return `<tr>
      <td><a class="lnk" href="/zone/${u(z)}/tx/${u(t.hash)}">${esc(sh(t.hash))}</a></td>
      <td>${visBadge(t)}</td>
      <td>${typeBadge(t)}</td>
      <td>${finalityBadge(t)||'<span class="mut">-</span>'}</td>
      <td class="mono">${blockCell}</td>
      <td class="mut nowrap">${ageOf(t)}</td>
      <td><a class="lnk" href="/zone/${u(z)}">${chanLabel(z, t.channel_short)}</a></td>
      <td>${accs}</td></tr>`;
  }).join('');
}
const txHead='<thead><tr><th>Txn Hash</th><th>Visibility</th><th>Type</th><th>Status</th><th>Block</th><th>Age</th><th>Zone</th><th>Accounts</th></tr></thead>';
const crumb=(parts)=>`<div style="font-size:13px;color:var(--soft);padding:14px 0 10px">${parts.map((p,i)=>(i?' <span style="color:var(--soft)">/</span> ':'')+(p.href?`<a href="${p.href}">${esc(p.t)}</a>`:`<span style="color:var(--fg)">${esc(p.t)}</span>`)).join('')}</div>`;

// ---- reusable infinite-scroll tx feed (appends into #rows; updates #count) ----
const PAGE=50;
// bind infinite scroll to the feed's own bounded container (.tscroll), not the window,
// so the page stays short and the footer sits at its end.
function attachFeedScroll(){
  const tb=$('rows'); const sc=tb&&tb.closest('.tscroll'); if(!sc) return;
  sc.onscroll=()=>{ const f=cur.feed; if(f&&!f.done&&!f.loading && sc.scrollTop+sc.clientHeight>=sc.scrollHeight-300) feedMore(); };
}
function cursorParams(p,cursor){ if(cursor){ if(cursor.ts!=null) p.set('before_ts',cursor.ts); p.set('before_block',cursor.block); p.set('before_hash',cursor.hash); } return p; }
// buildUrl(cursor) -> the fetch URL for the next page (cursor=null for the first).
function txFeed(buildUrl){
  cur.feed={buildUrl, cursor:null, done:false, loading:false, count:0, first:true, seen:new Set()};
  const tb=$('rows'); if(tb) tb.innerHTML='<tr><td colspan="8" class="empty">loading…</td></tr>';
  attachFeedScroll();
  feedMore();
}
async function feedMore(){
  const f=cur.feed; if(!f||f.loading||f.done) return; f.loading=true;
  // show a loading row at the bottom while the next page is in flight (not on first load)
  const tb0=$('rows');
  if(tb0&&!f.first) tb0.insertAdjacentHTML('beforeend','<tr class="loadrow" id="loadrow"><td colspan="8">loading<span class="dot"></span><span class="dot"></span><span class="dot"></span></td></tr>');
  try{
    const resp=await (await fetch(f.buildUrl(f.cursor))).json();
    const list=Array.isArray(resp)?resp:(resp.txs||[]); // /api/txs returns an array; account/token an object
    const tb=$('rows'); if(!tb||cur.feed!==f){ f.loading=false; return; }
    const lr=$('loadrow'); if(lr) lr.remove();
    if(f.first){ f.first=false; tb.innerHTML=''; }
    if(list.length){ tb.insertAdjacentHTML('beforeend', txRows(list)); f.count+=list.length;
      list.forEach(t=>f.seen&&f.seen.add(t.hash));
      const last=list[list.length-1]; f.cursor={ts:last.timestamp, block:last.block_id, hash:last.hash}; }
    if(!f.count) tb.innerHTML=`<tr><td colspan="8" class="empty">${state&&state.discovering?'⏳ scanning recent L1 blocks…':'no transactions'}</td></tr>`;
    if(list.length<PAGE) f.done=true;
    const cnt=$('count'); if(cnt) cnt.textContent='';
  }catch(e){ const lr=$('loadrow'); if(lr) lr.remove(); }
  f.loading=false;
}
// reload the feed in place if scrolled near the top (so it stays live without
// disrupting a user who has scrolled down into history).
function txFeedLiveTick(buildUrl){ if(window.scrollY<200 && (!cur.feed||!cur.feed.loading)) txFeed(buildUrl); }
// attach infinite scroll to a page that already rendered its first page of `list`.
function attachScroll(buildUrl, list){
  cur.feed={buildUrl, cursor:list.length?{ts:list[list.length-1].timestamp,block:list[list.length-1].block_id,hash:list[list.length-1].hash}:null,
    done:list.length<PAGE, loading:false, count:list.length, first:false, seen:new Set(list.map(t=>t.hash))};
  attachFeedScroll();
}
// live updates: new txs pushed over SSE slide in at the top (home + zone feeds).
function clockOk(t){ return FLT.types.has('clock') || progName(t.program)!=='clock'; }
// With a single tracked zone the home feed IS that zone's feed, so scope it to that
// channel: the home (`/`) and zone (`/zone/:id`) views then draw from the identical
// `/api/txs` query + the same live-update set, so they never diverge as blocks stream.
function soloChannel(){ const s=state&&state.sequencers; return (s&&s.length===1)?s[0].channel:null; }
function feedMatches(t){
  if(cur.kind==='zone'){ if(t.channel!==cur.seq) return false; }
  else if(cur.kind==='home'){ const solo=soloChannel(); if(solo && t.channel!==solo) return false; }
  else return false;
  if(!filterMatches(t)) return false;
  // clock hidden unless the "clock" type chip is selected (clockOk checks FLT)
  if(!clockOk(t)) return false;
  return true;
}
function prependTxs(txs){
  const f=cur.feed, tb=$('rows'); if(!f||!tb||!f.seen) return;
  const add=[];
  for(const t of txs){ if(!f.seen.has(t.hash) && feedMatches(t)){ f.seen.add(t.hash); add.push(t); } }
  if(!add.length) return;
  if(tb.querySelector('td.empty')) tb.innerHTML='';
  tb.insertAdjacentHTML('afterbegin', txRows(add)); f.count+=add.length;
  const cnt=$('count'); if(cnt) cnt.textContent='';
}

// ---- header (always) ----
function renderHeader(){
  if(!state) return;
  $('node').textContent=state.node; $('node').title=state.node;
  const l1=state.l1, dot=$('statdot'), mode=$('statmode');
  if(!l1.reachable){ dot.className='dot dead'; mode.textContent='L1 unreachable'; }
  else if(l1.mode && l1.mode!=='online'){ dot.className='dot off'; mode.textContent='L1 '+(l1.mode==='bootstrapping'?'syncing':l1.mode); }
  else if(l1.advancing===false){ dot.className='dot off'; mode.textContent='L1 not advancing'; }
  else { dot.className='dot on'; mode.textContent=l1.synced===true?'L1 synced':'L1 online'; }
  const ver=$('statver');
  if(ver){
    if(l1.reachable && l1.l1_version){ ver.textContent='L1 v'+l1.l1_version; ver.style.display=''; }
    else { ver.style.display='none'; }
  }
  $('foot').innerHTML='reads only public on-chain settlement data · updated '+fmtAge(state.updated_unix)+' · '+
    (state.decode_feature?'tx decode on':'tx decode off - rebuild with <code>--features decode</code>');
}

// ---- views ----
let cur={kind:'home'};

function renderHome(){
  cur={kind:'home'};
  const l1=state?state.l1:{}, seqs=(state&&state.sequencers)||[];
  const alive=seqs.filter(s=>s.alive).length;
  $('view').innerHTML=`
  <div class="cards">
    <div class="card"><div class="k">L1 Block Height</div><div class="v">${num(l1.height)}</div><div class="s">${l1.advancing===false?'not advancing':(l1.reachable?'advancing':'-')}</div></div>
    <div class="card"><div class="k">Finality Lag</div><div class="v">${num(l1.finality_lag)}</div><div class="s">tip slot ${num(l1.tip_slot)}</div></div>
    <div class="card"><div class="k">Transactions</div><div class="v">${num(state&&state.tx_total)}</div><div class="s">${state&&state.decode_feature?'decode on':'decode off'}</div></div>
    <div class="card"><div class="k">Zones</div><div class="v">${num(seqs.length)}</div><div class="s">${alive} active</div></div>
  </div>
  <div class="grid">
    <div class="panel"><div class="phead">Zones</div><div id="seqs"></div></div>
    <div class="panel">
      <div class="phead"><span>Latest Transactions</span>
        <span style="display:flex;align-items:center;gap:10px">
        ${state&&state.skip_clock?'<span class="mut" style="font-size:12px;white-space:nowrap" title="clock txs tick every block and are not stored">clock ticks not indexed</span>':''}
        <span class="count" id="count"></span></span></div>
      ${filterBar()}
      <div class="tscroll"><table class="ttbl">${txHead}<tbody id="rows"><tr><td colspan="8" class="empty">loading…</td></tr></tbody></table></div>
    </div>
  </div>`;
  wireFilter(()=>txFeed(homeFeedUrl));
  renderSeqs(); txFeed(homeFeedUrl);
}
function homeFeedUrl(cursor){
  const p=new URLSearchParams(); p.set('limit',PAGE);
  const solo=soloChannel(); if(solo) p.set('channel',solo); // one zone => same query as /zone/:id
  filterParams(p);
  return '/api/txs?'+cursorParams(p,cursor);
}
function renderSeqs(){
  const seqs=(state&&state.sequencers)||[]; const el=$('seqs'); if(!el) return;
  if(!cur.seqShown) cur.seqShown=60;
  const slice=seqs.slice(0,cur.seqShown);
  el.innerHTML = seqs.length ? slice.map(s=>`<a class="srow" href="/zone/${u(s.channel)}" style="text-decoration:none;color:inherit">
      <span class="dot ${s.alive?'on':'off'}"></span>
      <div class="sm"><div class="a">${esc(zoneTitle(s))}${consBadge(s)}</div>
        <div class="zmeta"><span class="zf"><span class="zk">Channel ID</span> <span class="chex">${esc(s.channel_short)}</span></span><span class="zf"><span class="zk">Sequencer version</span> ${verValue(s)}</span></div>
        <div class="b">L2 ${l2Tip(s)} · L1 bal ${s.l1_balance!=null?num(s.l1_balance):'-'} · ${s.l1_signers||0} key(s)${tipNote(s)}${activityChip(s)}</div></div>
      <span class="st ${s.alive?'alive':'idle'}">${s.alive?'ALIVE':'IDLE'}</span></a>`).join('')
      + (seqs.length>cur.seqShown?`<div class="empty" style="padding:12px">scroll for ${seqs.length-cur.seqShown} more…</div>`:'')
    : `<div class="empty">${state&&state.discovering?'scanning the L1 for sequencers…':'no sequencers found'}</div>`;
  el.onscroll=()=>{ if(el.scrollTop+el.clientHeight>=el.scrollHeight-100 && cur.seqShown<seqs.length){ cur.seqShown+=60; renderSeqs(); } };
}

// The L2 tip to display: a real height, else an em dash for a channel with activity but no
// L2 block height (e.g. only raw inscriptions), else block zero (a genesis-only channel).
function l2Tip(s){ return (s&&s.latest_block_id>0)?'#'+num(s.latest_block_id):(s&&s.activity_state?'—':'#0'); }

// Small zones-list chip mirroring the activity_state (honest, never implies user txs).
function activityChip(s){
  const st=s&&s.activity_state; if(!st) return '';
  const m={finalizing:['safe','finalizing','on-L1 inscriptions awaiting finality'],
           'clock-only':['pend','clock-only','idle — clock heartbeats only'],
           raw:['safe','raw','raw text/data inscriptions (not sequencer blocks) — shown as rows']}[st];
  if(!m) return '';
  return ` · <span class="fbadge ${m[0]}" style="font-size:9px;padding:0 5px" title="${esc(m[2])}">${esc(m[1])}</span>`;
}

// Honest explainer panel for a channel that shows NO user-tx rows but has activity. Three
// server-classified states (activity_state), each worded so we never imply user txs that
// aren't there: "finalizing" (recent, not-yet-final — contents unknown), "clock-only"
// (idle heartbeats), "raw" (non-block raw inscriptions, now also shown as their own rows).
function activityPanel(s){
  const st=s&&s.activity_state; if(!st) return '';
  const lib=(state&&state.l1&&state.l1.lib_slot)||0;
  const tip=s.l1_tip_slot||0, start=s.l1_tip_start_slot||0;
  const n=s.inscriptions_seen||0, nS=n>0?num(n)+' ':'';
  const keys=s.accredited_keys||[];
  const insc=keys.length?keys.map(k=>`<code title="${esc(k)}">${esc(sh(k,10,6))}</code>`).join(', '):'<span class="mut">-</span>';
  const thr=s.config_threshold!=null?` <span class="mut" style="font-size:11px">· ${num(s.config_threshold)} of ${keys.length||'?'} to inscribe</span>`:'';
  const tiph=s.tip_message?`<code title="${esc(s.tip_message)}">${esc(sh(s.tip_message,10,6))}</code>`:'<span class="mut">-</span>';
  let badge,headline,note,extra='';
  if(st==='finalizing'){
    const gap=tip>lib?tip-lib:0;
    const eta=gap>0?`${num(gap)} slot${gap===1?'':'s'} to finalize (~${Math.max(1,Math.round(gap/60))} min)`:'finalizing now';
    badge='<span class="fbadge safe" title="settled on the L1, awaiting finality">on L1 · finalizing</span>';
    headline=`${nS}inscription${n===1?'':'s'} · finalizing`;
    note='Recent inscriptions are settled on the L1 but not yet finalized. Their contents become visible once finalized — they may be clock heartbeats or user transactions; unknown until then. New inscriptions appear live.';
    extra=`<div class="k">Finality</div><div class="v">${esc(eta)} <span class="mut" style="font-size:11px">(tip slot ${num(tip)} vs last-final ${num(lib)})</span></div>`;
  } else if(st==='clock-only'){
    badge='<span class="fbadge pend" title="settling only clock heartbeats">idle · clock-only</span>';
    headline=`clock-only · ${nS}heartbeat inscription${n===1?'':'s'} · no user txs`;
    note='This channel has settled only clock heartbeats in the scanned window — no user transactions. Clock ticks are hidden from the feed.';
  } else {
    badge='<span class="fbadge safe" title="raw text/data inscriptions - not sequencer blocks">raw inscriptions</span>';
    headline=`${nS}raw inscription${n===1?'':'s'} · not a sequencer block`;
    note='This channel settles raw text/data inscriptions rather than sequencer blocks. Each is listed below as its own inscription row — open one to read its content (decoded UTF-8 text, or a hex dump). New inscriptions appear live.';
  }
  return `<div class="panel" style="margin-bottom:16px">
    <div class="phead">Channel activity ${badge}</div>
    <div style="padding:14px 18px 2px;font-weight:600;color:var(--navy)">${esc(headline)}</div>
    <div class="kv" style="padding:12px 18px 4px">
      <div class="k">Activity (L1 slots)</div><div class="v">${num(start)} → ${num(tip)}</div>
      ${extra}
      <div class="k">Inscriber</div><div class="v">${insc}${thr}</div>
      <div class="k">Tip hash</div><div class="v">${tiph}</div>
      <div class="k">Channel balance</div><div class="v">${s.l1_balance!=null?num(s.l1_balance):'-'}</div>
    </div>
    <div class="mut" style="padding:6px 18px 16px;font-size:12px;line-height:1.55">${esc(note)}</div>
  </div>`;
}

async function renderZone(seq){
  cur={kind:'zone',seq};
  const s=((state&&state.sequencers)||[]).find(x=>x.channel===seq)||{channel:seq,channel_short:sh(seq)};
  $('view').innerHTML=`${crumb([{t:'Home',href:'/'},{t:'Zone '+sh(seq)}])}
  <div class="panel" style="margin-bottom:16px"><div class="phead">Sequencer ${chanLabel(s.channel, s.channel_short)} ${verBadge(s)}${consBadge(s)}</div>
    <div class="ovw">
      <div><div class="k">Latest L2 Block</div><div class="v">${l2Tip(s)}</div></div>
      <div><div class="k">L1 Channel Balance</div><div class="v">${s.l1_balance!=null?num(s.l1_balance):'-'}</div></div>
      <div><div class="k">Status</div><div class="v" style="color:${s.alive?'var(--green)':'var(--soft)'}">${s.alive?'ALIVE':'IDLE'}</div></div>
    </div>
    <div class="kv" style="padding:16px">
      <div class="k">Channel id</div><div class="v">${esc(seq)}</div>
      <div class="k">LEZ Version</div><div class="v">${s.version?esc(s.version):'-'}</div>
      <div class="k">Last settled</div><div class="v">${s.tip_change_unix?fmtAge(s.tip_change_unix):'-'} <span class="mut" style="font-size:11px">(channel tip)</span></div>
      <div class="k">Signer keys</div><div class="v">${num(s.l1_signers)}</div>
      <div class="k">Sequencer tip (RPC)</div><div class="v">${s.seq_tip!=null?'#'+num(s.seq_tip)+(s.seq_tip<s.latest_block_id?' ⚠ below L1':''):'-'}</div>
      <div class="k">Chain check</div><div class="v">${esc(chainCheckText(s))}</div>
      <div class="k">Inscriptions seen</div><div class="v">${num(s.inscriptions_seen)}</div>
    </div>
  </div>
  ${activityPanel(s)}
  <div class="panel"><div class="phead">Transactions <span class="count" id="count"></span>
    ${state&&state.skip_clock?'<span class="mut" style="margin-left:12px;font-weight:400;font-size:12px" title="clock txs tick every block and are not stored">clock ticks not indexed</span>':''}</div>
    ${filterBar()}
    <div class="tscroll"><table class="ttbl">${txHead}<tbody id="rows"><tr><td colspan="8" class="empty">loading…</td></tr></tbody></table></div></div>`;
  cur.feedUrl=(cursor)=>{ const p=new URLSearchParams(); p.set('channel',seq); p.set('limit',PAGE);
    filterParams(p); return '/api/txs?'+cursorParams(p,cursor); };
  wireFilter(()=>txFeed(cur.feedUrl));
  txFeed(cur.feedUrl);
}

// group a hex string into space-separated byte pairs, 32 bytes per line, for a readable dump.
function fmtHex(h){ h=(h||'').replace(/[^0-9a-fA-F]/g,''); const bytes=h.match(/.{1,2}/g)||[]; let out='';
  for(let i=0;i<bytes.length;i+=32){ out+=bytes.slice(i,i+32).join(' ')+'\n'; } return out.replace(/\n$/,''); }
// tx-detail content block for a raw inscription: its bytes as decoded UTF-8 text (when
// printable) or a hex dump. No fabricated decoded fields - just the on-chain content.
function rawPayloadPanel(t){
  const hasText=t.raw_text!=null && t.raw_text!=='';
  const body=hasText?`<pre class="rawtext">${esc(t.raw_text)}</pre>`
                    :`<pre class="rawhex">${esc(fmtHex(t.raw_hex||''))}</pre>`;
  return `<div class="panel" style="margin-top:16px"><div class="phead">Raw inscription payload <span class="mut" style="font-weight:400;font-size:12px">${t.raw_len?num(t.raw_len)+' bytes · ':''}${hasText?'UTF-8 text':'binary (hex)'}</span></div>
    <div style="padding:14px 18px 18px">
      <div class="mut" style="font-size:12px;margin-bottom:9px;line-height:1.5">A raw text/data inscription — not a sequencer block. The bytes below are its on-chain content, shown ${hasText?'as decoded UTF-8 text':'as a hex dump'}.</div>
      ${body}
    </div></div>`;
}

async function renderTx(seq,hash){
  cur={kind:'tx'};
  $('view').innerHTML=crumb([{t:'Home',href:'/'},{t:'Zone '+sh(seq),href:'/zone/'+u(seq)},{t:'Tx '+sh(hash)}])+'<div class="panel"><div class="empty">loading transaction…</div></div>';
  let t; try{ const r=await fetch('/api/tx/'+u(hash)); if(r.ok) t=await r.json(); }catch(e){}
  if(!t){ $('view').innerHTML=crumb([{t:'Home',href:'/'},{t:'Zone '+sh(seq),href:'/zone/'+u(seq)},{t:'Tx '+sh(hash)}])+'<div class="panel"><div class="empty">transaction not found in the current window</div></div>'; return; }
  const z=t.channel||seq;
  const taMap={}; (t.token_accounts||[]).forEach(x=>{ taMap[x.account]=x; }); // account -> {symbol, role}
  const accLinks=(arr)=> arr&&arr.length?`<div class="chips">${arr.map(x=>{
    const ta=taMap[x];
    return `<a href="/zone/${u(z)}/wallet/${u(x)}">${esc(x)}${ta?` <span class="mut">· <b>${esc(ta.symbol)}</b> ${esc(ta.role)}</span>`:''}</a>`;
  }).join('')}</div>`:'<span class="mut">none</span>';
  const li=(arr)=> arr&&arr.length?`<div class="chips">${arr.map(x=>`<span>${esc(x)}</span>`).join('')}</div>`:'<span class="mut">none</span>';
  $('view').innerHTML=crumb([{t:'Home',href:'/'},{t:'Zone '+sh(z),href:'/zone/'+u(z)},{t:'Tx '+sh(hash)}])+
   `<div class="panel"><div class="phead">Transaction ${visBadge(t)} ${typeBadge(t)}</div>
    <div style="padding:16px 18px 2px;font-size:17px;font-weight:600;color:var(--navy)">${txAction(t)} ${finalityBadge(t)}</div>
    <div class="kv" style="padding:14px 18px 18px">
    <div class="k">Txn Hash</div><div class="v">${esc(t.hash)}</div>
    <div class="k">Visibility</div><div class="v">${cap(txVis(t))}</div>
    <div class="k">Type</div><div class="v">${(()=>{const g=(t.kind==='public')?guessFor(t.program,t):null;return g?guessHtml(g):esc(typeLabel(txType(t)));})()}</div>
    ${t.program?`<div class="k">Program</div><div class="v"><a class="lnk" href="/zone/${u(z)}/program/${u(t.program)}" title="${esc(t.program)}">${(()=>{const g=guessFor(t.program,t);return g?guessHtml(g)+` <span class="mut mono" style="font-size:11px">${esc(sh(t.program,6,5))}</span>`:esc(progShort(t.program));})()}</a></div>`:''}
    <div class="k">${t.kind==='raw'?'Channel':'Sequencer'}</div><div class="v"><a class="lnk" href="/zone/${u(z)}">${esc(z)}</a></div>
    ${t.kind==='raw'
      ?`<div class="k">L1 slot</div><div class="v">${t.slot?num(t.slot):'—'}</div>`
      :`<div class="k">L2 Block</div><div class="v">#${num(t.block_id)}${t.slot?'  ·  L1 slot '+num(t.slot):''}</div>
    <div class="k">Accounts (${(t.accounts||[]).length})</div><div class="v">${accLinks(t.accounts)}</div>`}
    ${t.instruction_data&&t.instruction_data.length?`<div class="k">Instruction</div><div class="v" id="instrval">${instrText(t,null)}</div>`:''}
    ${t.deploy_program?`<div class="k">Deploys program</div><div class="v"><a class="lnk" href="/zone/${u(z)}/program/${u(t.deploy_program)}" title="${esc(t.deploy_program)}">${esc(progShort(t.deploy_program))}</a></div>`:''}
    ${t.bytecode_len?`<div class="k">Guest ELF</div><div class="v">${num(t.bytecode_len)} bytes · <a class="lnk" href="/api/elf/${u(t.hash)}" download>download .elf</a></div>`:''}
    ${t.nullifiers&&t.nullifiers.length?`<div class="k">Nullifiers (${t.nullifiers.length})</div><div class="v">${li(t.nullifiers)}</div>`:''}
    ${t.commitments&&t.commitments.length?`<div class="k">Commitments (${t.commitments.length})</div><div class="v">${li(t.commitments)}</div>`:''}
    ${t.encrypted_outputs!=null?`<div class="k">Encrypted outputs</div><div class="v">${t.encrypted_outputs} (private, opaque)</div>`:''}
   </div></div>${t.kind==='raw'?rawPayloadPanel(t):''}`;
  // token-standard transfer: resolve which token (name) via the holding account, then refine
  if(progName(t.program)==='token' && t.instruction_data && t.instruction_data.length>=5 && t.instruction_data[0]===0 && t.accounts && t.accounts[0]){
    try{ const tok=await (await fetch('/api/token_of?account='+u(t.accounts[0])+'&channel='+u(z))).json();
      const el=$('instrval'); if(el && cur.kind==='tx') el.innerHTML=instrText(t,tok);
    }catch(e){}
  }
  // custom/deployed program, no registered schema: infer a tentative field layout from
  // the program's instruction corpus and decode this tx by it (variant · fixed · id · …).
  const BUILTIN=['token','amm','clock','pinata','pinata_token','ata','authenticated_transfer','privacy_preserving_circuit'];
  if(t.program && t.instruction_data && t.instruction_data.length && !SCHEMAS[t.program] && !BUILTIN.includes(progName(t.program))){
    try{ const lay=await ensureLayout(t.program, z);
      const html=lay && renderByLayout(t.instruction_data, lay, t);
      const el=$('instrval'); if(html && el && cur.kind==='tx') el.innerHTML=html;
    }catch(e){}
  }
}

async function renderProgram(seq,prog){
  cur={kind:'program'};
  const g=guessFor(prog,null);
  const nameCell=g?guessHtml(g):esc(progShort(prog));
  const base=[{t:'Home',href:'/'},{t:'Zone '+sh(seq),href:'/zone/'+u(seq)},{t:'Program '+(g?('≈ '+g.name):progShort(prog))}];
  $('view').innerHTML=crumb(base)+
   `<div class="panel" style="margin-bottom:16px"><div class="phead">Program <span class="count">${nameCell}</span></div>
    <div class="ovw">
      <div><div class="k">Program</div><div class="v" style="font-size:15px;word-break:break-all">${nameCell}</div></div>
      <div><div class="k">Sequencer</div><div class="v" style="font-size:13px"><a class="lnk" href="/zone/${u(seq)}">${esc(sh(seq))}</a></div></div>
    </div>
    ${g?`<div class="kv" style="padding:0 16px 4px"><div class="k">Name</div><div class="v"><span class="pguess">≈ ${esc(g.name)}</span> <span class="mut" style="font-size:12px">best-guess from tx fingerprint — unverified · ${Math.round((g.confidence||0)*100)}% confidence${g.samples?' · '+g.samples+' tx'+(g.samples===1?'':'s'):''}</span></div></div>`:''}
    <div class="kv" style="padding:16px"><div class="k">Program id</div><div class="v">${esc(prog)}</div></div>
   </div>
   ${schemaPanel(seq,prog)}
   <div class="panel"><div class="phead">Transactions <span class="count" id="count"></span></div>
    <div class="tscroll"><table class="ttbl">${txHead}<tbody id="rows"></tbody></table></div></div>`;
  txFeed((cursor)=>{ const p=new URLSearchParams(); p.set('channel',seq); p.set('program',prog); p.set('limit',PAGE); p.set('clock','1'); return '/api/txs?'+cursorParams(p,cursor); });
}
// instruction-schema panel: show a registered schema, or (for an unresolved custom
// program) an open submission form - validated against the program's real instructions.
function schemaPanel(seq,prog){
  const isCustom = prog && /^[0-9a-f]{64}$/i.test(prog);
  const have = SCHEMAS[prog];
  if(have) return `<div class="panel" style="margin-bottom:16px"><div class="phead">Instruction schema</div>
    <div style="padding:16px"><div class="mut" style="font-size:12px;margin-bottom:8px">A schema is registered - instructions decode into typed fields.</div>
    <pre class="mono" style="font-size:12px;background:var(--panel2,#f4f4f5);padding:10px;border-radius:6px;overflow:auto;margin:0">${esc(JSON.stringify(have,null,2))}</pre></div></div>`;
  if(!isCustom) return '';
  return `<div class="panel" style="margin-bottom:16px"><div class="phead">Instruction schema (ABI) <span class="count">propose</span></div>
    <div style="padding:16px">
      <div class="hint" style="margin-bottom:8px">No schema yet, so instructions show as raw words. Anyone can propose one - paste the program's <b>instruction type</b>. It's accepted only if it decodes this program's <b>real on-chain instructions exactly</b>. Examples: <code>{"struct":[{"name":"message","type":"bytes"}]}</code> · <code>{"enum":[{"name":"Greet","fields":[{"name":"msg","type":"string"}]}]}</code></div>
      <textarea id="schemainput" rows="3" placeholder='{"struct":[{"name":"message","type":"bytes"}]}' style="width:100%;box-sizing:border-box;font-family:var(--mono);font-size:12px;padding:9px;border:1px solid var(--line2);border-radius:6px"></textarea>
      <div style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <button class="kbtn" onclick="previewSchema('${esc(seq)}','${esc(prog)}')">Preview</button>
        <button class="kbtn sel" onclick="submitSchema('${esc(seq)}','${esc(prog)}')">Validate &amp; submit</button>
        <span id="schemamsg" style="font-size:12px"></span></div>
      <div id="schemapreview" style="margin-top:8px"></div>
    </div></div>`;
}
function getSchemaInput(){ try{ const v=$('schemainput').value.trim(); return v?JSON.parse(v):null; }catch(e){ return undefined; } }
async function previewSchema(seq,prog){
  const sc=getSchemaInput(), el=$('schemapreview');
  if(sc===undefined){ el.innerHTML='<span style="color:var(--red)">invalid JSON</span>'; return; }
  if(sc===null){ el.innerHTML=''; return; }
  el.innerHTML='<span class="mut">decoding samples…</span>';
  try{
    const txs=await (await fetch('/api/txs?channel='+u(seq)+'&program='+u(prog)+'&clock=1&limit=8')).json();
    const rows=txs.filter(t=>t.instruction_data&&t.instruction_data.length).slice(0,8).map(t=>{
      const w=t.instruction_data, r=r0dec(w,sc,0), full=(r.p===w.length);
      return `<div class="mono" style="font-size:12px;padding:2px 0">${full?'<span style="color:var(--green)">✓</span>':'<span style="color:var(--red)">✗</span>'} ${decodeBySchema(w,sc)||'<span class="mut">(decode error)</span>'}${full?'':` <span style="color:var(--red)">- consumed ${r.p}/${w.length} words</span>`}</div>`;
    }).join('');
    el.innerHTML=rows||'<span class="mut">no instructions to preview</span>';
  }catch(e){ el.innerHTML='<span class="mut">preview failed</span>'; }
}
async function submitSchema(seq,prog){
  const sc=getSchemaInput(), msg=$('schemamsg');
  if(sc===undefined){ msg.innerHTML='<span style="color:var(--red)">invalid JSON</span>'; return; }
  if(sc===null){ msg.innerHTML='<span class="mut">paste a schema first</span>'; return; }
  msg.textContent='validating…';
  try{
    const r=await (await fetch('/api/schemas/submit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({channel:seq,program_id:prog,instruction:sc})})).json();
    if(!r.ok){ msg.innerHTML='<span style="color:var(--red)">'+esc(r.error||'error')+'</span>'; }
    else if(r.stored){ msg.innerHTML='<span style="color:var(--green)">✓ accepted ('+r.passed+'/'+r.tested+' instructions) - reloading…</span>'; await loadSchemas(); setTimeout(()=>renderProgram(seq,prog),1100); }
    else if(r.already_exists){ msg.innerHTML='<span class="mut">a schema is already registered for this program</span>'; }
    else { msg.innerHTML='<span style="color:var(--red)">✗ rejected - decodes only '+r.passed+'/'+r.tested+' instructions exactly</span>'; }
  }catch(e){ msg.textContent='error: '+e; }
}

async function renderToken(seq,tid){
  cur={kind:'token'};
  const base=[{t:'Home',href:'/'},{t:'Zone '+sh(seq),href:'/zone/'+u(seq)},{t:'Token '+sh(tid)}];
  $('view').innerHTML=crumb(base)+'<div class="panel"><div class="empty">loading token…</div></div>';
  let a; try{ const p=new URLSearchParams(); p.set('channel',seq); filterParams(p);
    a=await (await fetch('/api/token/'+u(tid)+'?'+p.toString())).json(); }catch(e){}
  if(!a){ $('view').innerHTML=crumb(base)+'<div class="panel"><div class="empty">token not found</div></div>'; return; }
  $('view').innerHTML=crumb(base)+
   `<div class="panel" style="margin-bottom:16px"><div class="phead">Token <span class="count">${esc(a.name||sh(tid))}</span></div>
    <div class="ovw">
      <div><div class="k">Name</div><div class="v">${esc(a.name||'-')}</div></div>
      <div><div class="k">Type</div><div class="v" style="font-size:15px">${esc(a.kind||'-')}</div></div>
      <div><div class="k">Total supply</div><div class="v">${a.supply&&a.supply!=='0'?num(a.supply):'-'}</div></div>
    </div>
    <div class="kv" style="padding:16px"><div class="k">Definition account</div><div class="v">${esc(tid)}</div>
      <div class="k">Sequencer</div><div class="v"><a class="lnk" href="/zone/${u(seq)}">${esc(sh(seq))}</a></div></div>
   </div>
   <div class="panel"><div class="phead">Transactions <span class="count" id="count">${num(a.tx_count)}</span></div>
    ${filterBar()}
    <div class="tscroll"><table class="ttbl">${txHead}<tbody id="rows">${txRows(a.txs)}</tbody></table></div></div>`;
  const tokUrl=(cursor)=>{ const p=new URLSearchParams(); p.set('channel',seq); p.set('limit',PAGE);
    filterParams(p); return '/api/token/'+u(tid)+'?'+cursorParams(p,cursor); };
  attachScroll(tokUrl, a.txs||[]);
  wireFilter(()=>renderToken(seq,tid));
}

async function renderWallet(addr,seq){
  cur={kind:'wallet'};
  const base=seq?[{t:'Home',href:'/'},{t:'Zone '+sh(seq),href:'/zone/'+u(seq)},{t:'Wallet '+sh(addr)}]:[{t:'Home',href:'/'},{t:'Wallet '+sh(addr)}];
  $('view').innerHTML=crumb(base)+'<div class="panel"><div class="empty">loading account…</div></div>';
  let a; try{ const p=new URLSearchParams(); if(seq) p.set('channel',seq); filterParams(p); const qs=p.toString();
    a=await (await fetch('/api/account/'+u(addr)+(qs?'?'+qs:''))).json(); }catch(e){}
  if(!a){ $('view').innerHTML=crumb(base)+'<div class="panel"><div class="empty">account not found</div></div>'; return; }
  const muted=(t)=>`<span class="mut" style="font-size:14px;font-weight:400">${t}</span>`;
  const l2 = a.l2_balance!=null
    ? esc(a.l2_balance)+' <span class="mut" style="font-size:11px;font-weight:400">sequencer RPC</span>'
    : muted(a.sequencer_rpc?'RPC unavailable':'no sequencer RPC');
  const l1 = a.l1_balance!=null
    ? esc(a.l1_balance)+(a.l1_balance_block?` <span class="mut" style="font-size:11px;font-weight:400">@ #${num(a.l1_balance_block)}</span>`:'')
    : muted('not settled / private');
  const chans=(a.channels||[]).map(c=>`<a class="lnk" href="/zone/${u(c.channel)}/wallet/${u(addr)}">${chanLabel(c.channel, c.channel_short)}</a> <span class="mut">(${num(c.tx_count)} tx)</span>`).join(' &nbsp; ')||'<span class="mut">none</span>';
  $('view').innerHTML=crumb(base)+
   `<div class="panel" style="margin-bottom:16px"><div class="phead">${seq?'Account on '+esc(sh(seq)):'Account'} <span class="count">${esc(sh(addr,10,8))}</span></div>
    <div class="ovw" style="grid-template-columns:repeat(4,1fr)">
      <div><div class="k">Balance · L2 (sequencer)</div><div class="v">${l2}</div></div>
      <div><div class="k">Balance · L1 (settled)</div><div class="v">${l1}</div></div>
      <div><div class="k">Nonce</div><div class="v">${a.nonce!=null?num(a.nonce):'-'}</div></div>
      <div><div class="k">Transactions${seq?' (here)':''}</div><div class="v">${num(a.tx_count)}</div></div>
    </div>
    <div class="kv" style="padding:16px"><div class="k">Address</div><div class="v">${esc(a.id)}</div>
      ${seq?'':`<div class="k">Sequencers</div><div class="v" style="font-family:inherit">${chans}</div>`}</div>
   </div>
   <div class="panel"><div class="phead">Transactions <span class="count" id="count">${num(a.tx_count)}</span></div>
    ${filterBar()}
    <div class="tscroll"><table class="ttbl">${txHead}<tbody id="rows">${txRows(a.txs)}</tbody></table></div></div>`;
  const acctUrl=(cursor)=>{ const p=new URLSearchParams(); if(seq) p.set('channel',seq); p.set('limit',PAGE);
    filterParams(p); return '/api/account/'+u(addr)+'?'+cursorParams(p,cursor); };
  attachScroll(acctUrl, a.txs||[]);
  wireFilter(()=>renderWallet(addr,seq));
}

// ---- router ----
function route(){
  window.onscroll=null; cur.feed=null;   // drop any prior infinite-scroll handler
  const p=location.pathname; let m;
  if(p==='/'||p===''){ renderHome(); return; }
  if(m=p.match(/^\/zone\/([^\/]+)\/tx\/([^\/]+)\/?$/)){ renderTx(decodeURIComponent(m[1]),decodeURIComponent(m[2])); return; }
  if(m=p.match(/^\/zone\/([^\/]+)\/wallet\/([^\/]+)\/?$/)){ renderWallet(decodeURIComponent(m[2]),decodeURIComponent(m[1])); return; }
  if(m=p.match(/^\/zone\/([^\/]+)\/program\/([^\/]+)\/?$/)){ renderProgram(decodeURIComponent(m[1]),decodeURIComponent(m[2])); return; }
  if(m=p.match(/^\/zone\/([^\/]+)\/token\/([^\/]+)\/?$/)){ renderToken(decodeURIComponent(m[1]),decodeURIComponent(m[2])); return; }
  if(m=p.match(/^\/zone\/([^\/]+)\/?$/)){ renderZone(decodeURIComponent(m[1])); return; }
  if(m=p.match(/^\/wallet\/([^\/]+)\/?$/)){ renderWallet(decodeURIComponent(m[1]),null); return; }
  renderHome();
}

// ---- search (route to the right page) ----
async function doSearch(){
  const v=$('q').value.trim(); if(!v) return;
  if(/^(0x)?[0-9a-fA-F]{64}$/.test(v)){
    const h=v.replace(/^0x/,'').toLowerCase();
    try{ const r=await fetch('/api/tx/'+u(h)); if(r.ok){ const t=await r.json(); location.href='/zone/'+u(t.channel)+'/tx/'+u(h); return; } }catch(e){}
    location.href='/zone/'+u(h); return;       // treat as a channel id
  }
  location.href='/wallet/'+u(v);               // otherwise an account
}
$('qbtn').addEventListener('click',doSearch);
$('q').addEventListener('keydown',e=>{ if(e.key==='Enter') doSearch(); });

// ---- init + live ----
async function loadState(){ try{ state=await (await fetch('/api/state')).json(); renderHeader(); }catch(e){} }
async function loadProgs(){ try{ PROGS=await (await fetch('/api/programs')).json()||{}; }catch(e){} }
async function loadGuesses(){ try{ GUESS=await (await fetch('/api/program_guesses')).json()||{}; }catch(e){} }
async function loadSchemas(){ try{ SCHEMAS=await (await fetch('/api/schemas')).json()||{}; }catch(e){} }
const es=new EventSource('/events');
es.onmessage=(e)=>{ try{ const m=JSON.parse(e.data);
  if(m.t==='snap'){ state=m.d; renderHeader(); if(cur.kind==='home') renderSeqs(); }
  else if(m.t==='txs'){ prependTxs(m.d); }
}catch(_){} };
(async()=>{ await Promise.all([loadState(),loadProgs(),loadGuesses(),loadSchemas()]); route(); })();
// the program registry is fetched from the sequencer RPC (async, over Tor) - keep
// retrying until it populates, then stop.
// the feed updates live via SSE (new txs slide in at the top); this just keeps the
// header fresh if the event stream blips and retries the program registry once. Guesses are
// recomputed server-side on an interval, so refresh them periodically too.
let guessTick=0;
setInterval(()=>{ if(!Object.keys(PROGS).length) loadProgs(); if((++guessTick%6)===0) loadGuesses(); renderHeader(); }, 5000);
</script>
<footer id="sfoot">
  <span><a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank" rel="noopener noreferrer">GPL-3.0</a> · <a href="https://github.com/paradoxcomputer" target="_blank" rel="noopener noreferrer">Paradox Computer</a></span>
  <a href="https://github.com/paradoxcomputer/zonescan" target="_blank" rel="noopener noreferrer" title="Source on GitHub" aria-label="GitHub"><svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>GitHub</a>
  <a href="https://www.npmjs.com/package/@paradoxcomputer/zonescan" target="_blank" rel="noopener noreferrer" class="npm" title="npm package" aria-label="npm"><svg viewBox="0 0 576 512" fill="currentColor" aria-hidden="true"><path d="M288 288h-32v-64h32v64zm288-128v192H288v32H160v-32H0V160h576zm-416 32H32v128h64v-96h32v96h32V192zm160 0H192v160h64v-32h64V192zm224 0H352v128h64v-96h32v96h32v-96h32v96h32V192z"/></svg>npm</a>
</footer>
</body></html>"#;

const ADMIN_HTML: &str = r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>zonescan · setup</title><link rel="icon" type="image/png" href="/logo.png">
<meta name="robots" content="noindex">
<meta name="theme-color" content='#18181b'>
<style>
  :root{--bg:#f4f4f5;--panel:#ffffff;--panel2:#f1f1f3;--line:#e6e6e9;--line2:#d4d4da;
    --fg:#18181b;--muted:#6e6e77;--green:#3d8c40;--blue:#18181b;--mono:ui-monospace,Menlo,monospace;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:760px;margin:0 auto;padding:48px 22px}
  h1{font-size:22px;font-weight:600;margin:0 0 4px}h1 b{color:var(--blue)}
  .sub{color:var(--muted);margin:0 0 28px;font-size:13px}
  label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin:18px 0 6px}
  input{width:100%;background:var(--panel);border:1px solid var(--line2);border-radius:8px;color:var(--fg);
    font:13px var(--mono);padding:10px 12px;outline:none}
  input:focus{border-color:var(--blue)}
  .two{display:grid;grid-template-columns:1fr 200px;gap:16px}
  .seqrow{display:grid;grid-template-columns:110px 1fr 1fr auto 36px;gap:8px;margin-bottom:8px;align-items:center}
  .seqrow input{margin:0}
  .fullchk{display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted);white-space:nowrap;text-transform:none;letter-spacing:0;margin:0}
  .fullchk input{width:auto}
  .progrow{display:grid;grid-template-columns:1fr 220px 36px;gap:8px;margin-bottom:8px}
  .progrow input{margin:0}
  .rm{background:var(--panel2);border:1px solid var(--line);color:var(--muted);border-radius:8px;cursor:pointer}
  .add{margin-top:6px;background:none;border:1px dashed var(--line2);color:var(--muted);border-radius:8px;padding:8px 12px;cursor:pointer;font-size:12px}
  .actions{margin-top:28px;display:flex;align-items:center;gap:16px}
  .save{background:linear-gradient(180deg,#3a3a40,#161618);border:none;color:#fff;font-weight:600;border-radius:9px;padding:11px 20px;cursor:pointer;font-size:14px;box-shadow:0 2px 6px rgba(0,0,0,.18)}
  .save:hover{background:linear-gradient(180deg,#161618,#000)}
  .wrap{box-shadow:none}
  #msg{color:var(--muted);font-size:13px}
  .hint{color:var(--muted);font-size:12px;margin-top:6px}
  code{background:var(--panel2);padding:1px 5px;border-radius:4px;font-size:12px}
  .modes{display:inline-flex;border:1px solid var(--line2);border-radius:9px;overflow:hidden;margin:2px 0 4px}
  .mode{background:var(--panel);border:none;border-right:1px solid var(--line2);color:var(--muted);font:13px system-ui,-apple-system,sans-serif;padding:9px 16px;cursor:pointer}
  .mode:last-child{border-right:none}
  .mode.on{background:var(--fg);color:#fff;font-weight:600}
  .hide{display:none}
</style></head>
<body><div class="wrap">
  <h1 style="display:flex;align-items:center;gap:11px"><img src="/logo.png" alt="" style="width:36px;height:36px;filter:drop-shadow(0 1px 1px rgba(0,0,0,.18))"> <span><b>zone</b>scan · setup</span></h1>
  <p class="sub">Choose a data source, then the sequencer channel(s) to scan.</p>

  <label>Data source</label>
  <div class="modes">
    <button type="button" id="m-l1" class="mode on" onclick="setMode('l1')">L1 node</button>
    <button type="button" id="m-seq" class="mode" onclick="setMode('seq')">Local sequencer · no L1</button>
  </div>
  <div class="hint" id="modehint"></div>

  <div id="l1box">
    <label>L1 node URL</label>
    <input id="l1" placeholder="http://&lt;logos-node&gt;  ·  or an .onion (set SOCKS5 below)">
    <div class="hint">The L1 node the sequencers settle to (serves <code>/cryptarchia/info</code>, <code>/channel/:id</code>, <code>/cryptarchia/blocks</code>).</div>
    <label>SOCKS5 proxy (for .onion, optional)</label>
    <input id="socks" placeholder="127.0.0.1:9050">
  </div>

  <label id="disclabel">Discover window (slots)</label>
  <input id="disc" type="number" placeholder="6000" style="max-width:220px">
  <div class="hint" id="dischint"></div>

  <label style="display:flex;align-items:center;gap:9px;text-transform:none;letter-spacing:0;font-size:13px;color:var(--fg);margin-top:18px;cursor:pointer">
    <input id="full" type="checkbox" style="width:auto;margin:0;cursor:pointer"> Fetch full history (backfill every channel to genesis)
  </label>
  <div class="hint">Walks each channel's settled blocks all the way back to block #0 and persists them, instead of only the discover window - needed for sequencers whose recent activity sits beyond that window. It's resumable and the live stream keeps fetching new blocks regardless.</div>

  <label>Sequencers</label>
  <div class="hint" id="seqhint" style="margin:-2px 0 8px"></div>
  <div id="seqs"></div>
  <button class="add" onclick="addRow()">+ add sequencer</button>

  <label>Custom program names</label>
  <div class="hint" style="margin:-2px 0 8px">The sequencer only names its 5 built-ins (<code>token</code>, <code>amm</code>, <code>authenticated_transfer</code>, <code>pinata</code>, <code>privacy_preserving_circuit</code>). Deployed/custom programs have no on-chain name - label them here by their <b>64-hex program id</b> (an account's <code>program_owner</code>, shown on any tx that uses the program). These override the built-in registry too.</div>
  <div id="progs"></div>
  <button class="add" onclick="addProg()">+ add program name</button>

  <label>Custom program instruction schemas (ABI)</label>
  <div class="hint" style="margin:-2px 0 8px">Deployed programs have no on-chain instruction schema, so their instructions show as raw words. Paste the program's <b>instruction type</b> (its ABI) here to decode them. A type is a primitive (<code>u8</code>/<code>u16</code>/<code>u32</code>/<code>u64</code>/<code>u128</code>/<code>bool</code>/<code>string</code>/<code>bytes</code>) or an object - <code>{"struct":[{"name":"message","type":"bytes"}]}</code>, <code>{"enum":[{"name":"Greet","fields":[{"name":"msg","type":"string"}]}]}</code>, <code>{"vec":"u32"}</code>, <code>{"array":["u8",32]}</code>.</div>
  <div id="schemas"></div>
  <button class="add" onclick="addSchema()">+ add schema</button>

  <div class="actions"><button class="save" onclick="save()">Save &amp; start scanning</button><span id="msg"></span></div>
</div>
<script>
const $=id=>document.getElementById(id);
function row(s){ s=s||{}; const d=document.createElement('div'); d.className='seqrow';
  d.innerHTML=`<input class="lbl" placeholder="label" value="${(s.label||'').replace(/"/g,'&quot;')}">
    <input class="cid" placeholder="channel id (64 hex or alias)" value="${(s.channel_id||'').replace(/"/g,'&quot;')}">
    <input class="rpc" placeholder="sequencer RPC url (for exact balances)" value="${(s.rpc_url||'').replace(/"/g,'&quot;')}">
    <label class="fullchk" title="deep-walk this sequencer's full history back to genesis"><input type="checkbox" class="full" ${s.full?'checked':''}> full</label>
    <button class="rm" title="remove">✕</button>`;
  d.querySelector('.rm').onclick=()=>d.remove();
  $('seqs').appendChild(d); setRpcPh(d.querySelector('.rpc')); }
function addRow(){ row(); }
function prow(p){ p=p||{}; const d=document.createElement('div'); d.className='progrow';
  d.innerHTML=`<input class="pid" placeholder="program id (64 hex)" value="${(p.id||'').replace(/"/g,'&quot;')}">
    <input class="pname" placeholder="name" value="${(p.name||'').replace(/"/g,'&quot;')}">
    <button class="rm" title="remove">✕</button>`;
  d.querySelector('.rm').onclick=()=>d.remove();
  $('progs').appendChild(d); }
function addProg(){ prow(); }
function srow(s){ s=s||{}; const d=document.createElement('div'); d.className='schemarow'; d.style="display:flex;gap:8px;margin-bottom:8px;align-items:flex-start";
  d.innerHTML=`<input class="sid" placeholder="program id (64 hex)" value="${(s.id||'').replace(/"/g,'&quot;')}" style="flex:0 0 280px">
    <textarea class="sjson" rows="2" placeholder='{"struct":[{"name":"message","type":"bytes"}]}' style="flex:1;font-family:var(--mono);font-size:12px">${s.instruction?JSON.stringify(s.instruction).replace(/</g,'&lt;'):''}</textarea>
    <button class="rm" title="remove">✕</button>`;
  d.querySelector('.rm').onclick=()=>d.remove();
  $('schemas').appendChild(d); }
function addSchema(){ srow(); }
var LOADED={};
var MODE='l1';
const TOKEN=new URLSearchParams(location.search).get('token')||'';
const AUTH=TOKEN?{'X-Setup-Token':TOKEN}:{};
function setRpcPh(el){ if(el) el.placeholder = MODE==='seq' ? 'sequencer RPC url - REQUIRED (serves the blocks)' : 'sequencer RPC url (optional - exact balances)'; }
function setMode(m){ MODE=m;
  $('m-l1').classList.toggle('on',m==='l1'); $('m-seq').classList.toggle('on',m==='seq');
  $('l1box').classList.toggle('hide',m!=='l1');
  $('modehint').innerHTML = m==='l1'
    ? 'Read settlement data from a Logos <b>L1 node</b> - the trustless vantage onto every sequencer that settles to it.'
    : "No L1. Read blocks straight from each <b>sequencer's JSON-RPC</b> (<code>getBlock</code>) - works fully offline against a local sequencer.";
  $('disclabel').textContent = m==='l1' ? 'Discover window (slots)' : 'Backfill window (recent blocks)';
  $('dischint').innerHTML = m==='l1'
    ? 'Finalized L1 slots to seed on startup; the live stream keeps it current. Enable “full history” to backfill everything.'
    : 'Recent blocks to backfill per sequencer on startup. Enable “full history” to walk back to genesis.';
  $('seqhint').innerHTML = m==='l1'
    ? "Each = one sequencer. <b>Channel id</b> (64-hex or alias: dev, rc4, psychopomp) selects its txs on the L1. <b>RPC url</b> is optional - it fetches exact account balances. Leave the list empty to track every channel on the L1."
    : "Each = one sequencer to read directly. <b>Channel id</b> (64-hex or alias) identifies it; <b>RPC url</b> is <b>required</b> - the sequencer's JSON-RPC that serves its blocks.";
  document.querySelectorAll('.rpc').forEach(setRpcPh);
}
async function load(){
  try{ const c=await (await fetch('/api/config',{headers:AUTH})).json(); LOADED=c;
    $('l1').value=c.l1_node_url||''; $('socks').value=c.socks5||''; $('disc').value=c.discover_slots||''; $('full').checked=!!c.full_history;
    (c.sequencers||[]).forEach(row); if(!(c.sequencers||[]).length) row();
    (c.program_names||[]).forEach(prow);
    (c.program_schemas||[]).forEach(srow);
    setMode((!c.l1_node_url && (c.sequencers||[]).some(s=>s.rpc_url)) ? 'seq' : 'l1');
  }catch(e){ row(); setMode('l1'); }
}
async function save(){
  const seqMode = MODE==='seq';
  const cfg={ l1_node_url: seqMode ? '' : $('l1').value.trim(),
    socks5: seqMode ? null : ($('socks').value.trim()||null),
    discover_slots: $('disc').value? parseInt($('disc').value,10):null,
    full_history: $('full').checked,
    sequencers: [...document.querySelectorAll('.seqrow')].map(r=>({
      label:r.querySelector('.lbl').value.trim(),
      channel_id:r.querySelector('.cid').value.trim(),
      rpc_url:r.querySelector('.rpc').value.trim(),
      full:r.querySelector('.full').checked })).filter(s=>s.channel_id||s.label||s.rpc_url),
    program_names: [...document.querySelectorAll('.progrow')].map(r=>({
      id:r.querySelector('.pid').value.trim(),
      name:r.querySelector('.pname').value.trim() })).filter(p=>p.id&&p.name),
    program_schemas: [...document.querySelectorAll('.schemarow')].map(r=>{
      let inst=null; try{ inst=JSON.parse(r.querySelector('.sjson').value.trim()); }catch(e){}
      return { id:r.querySelector('.sid').value.trim(), instruction:inst }; }).filter(s=>s.id&&s.instruction!=null),
    discover_limit: LOADED.discover_limit!=null?LOADED.discover_limit:null };
  if(seqMode){ if(!cfg.sequencers.some(s=>s.rpc_url)){ $('msg').textContent='local-sequencer mode needs at least one sequencer with an RPC url'; return; } }
  else if(!cfg.l1_node_url){ $('msg').textContent='L1 node URL is required (or switch to “Local sequencer · no L1”)'; return; }
  $('msg').textContent='saving…';
  try{ const r=await fetch('/api/config',{method:'POST',headers:{'content-type':'application/json',...AUTH},body:JSON.stringify(cfg)});
    if(r.status===401){ $('msg').textContent='setup token required - open the /setup?token=… URL printed in the terminal'; return; }
    const j=await r.json();
    if(j.ok){ $('msg').textContent='saved - starting scan…'; setTimeout(()=>location.href='/',900); }
    else { $('msg').textContent='error: '+(j.error||'save failed'); }
  }catch(e){ $('msg').textContent='error: '+e; }
}
load();
</script>
</body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    // End-to-end for the guest `f8aab825…`: its 3 raw TEXT inscriptions must each become a
    // "raw" tx row keyed by the mantle_tx.hash (NOT a garbage block_id), be listed on the
    // channel (zone) feed, and be retrievable with their decoded content on the detail path.
    #[test]
    fn raw_inscriptions_become_rows_and_detail() {
        let channel = "f8aab825aabbccddeeff00112233445566778899aabbccddeeff001122334455";
        // (inscription id = mantle_tx.hash, L1 slot, ASCII content) — mirrors the real guest.
        let items = [
            ("f27e21db0000000000000000000000000000000000000000000000000000abcd", 187036u64, "dweb-via-paradox #1 17820"),
            ("58e3fc830000000000000000000000000000000000000000000000000000abcd", 187065, "dweb-via-paradox #2 17829"),
            ("1aa35a070000000000000000000000000000000000000000000000000000abcd", 187085, "dweb-via-paradox #3 17841"),
        ];

        let mut recs: Vec<TxRecord> = Vec::new();
        for (id, slot, text) in items {
            let block = serde_json::json!({
                "header": {"id": "abcd", "slot": slot},
                "transactions": [{"mantle_tx": {"hash": id, "ops": [
                    {"opcode": 17, "payload": {"channel_id": channel, "inscription": hex::encode(text.as_bytes())}}
                ]}}]
            });
            let mut found = Vec::new();
            collect_inscriptions(&block, &mut found);
            assert_eq!(found.len(), 1);
            let d = decode_inscription_with(&found[0].value, found[0].tx_hash.as_deref()).unwrap();
            assert!(d.undecodable, "raw text is not a decodable rc5 block");
            let out = records_from(channel, Some(slot), &d, 0);
            assert_eq!(out.len(), 1, "one raw tx per inscription");
            let r = &out[0];
            assert_eq!(r.hash, id, "keyed by the mantle_tx.hash, not a synthetic id");
            assert_eq!(r.kind, "raw");
            assert_eq!(r.block_id, 0, "no synthetic/garbage L2 block id");
            assert_eq!(r.slot, Some(slot));
            assert_eq!(r.raw_payload, text.as_bytes());
            recs.push(r.clone());
        }

        // persist + read back via the exact paths the zone page (channel feed) and the
        // tx-detail (get_tx) use.
        let path = std::env::temp_dir().join(format!("zs-raw-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = db::Db::open(&path).unwrap();
        db.commit(&recs, &[], &[], &[]).unwrap();

        // zone page: all 3 rows list under the channel feed.
        let feed = db
            .feed(&db::FeedOpts { channel: Some(channel), limit: 50, ..Default::default() })
            .unwrap();
        assert_eq!(feed.len(), 3, "guest zone page lists 3 raw-inscription rows");
        assert!(feed.iter().all(|r| r.kind == "raw"));

        // tx-detail: each hash resolves and its content decodes to the guest's text.
        for (id, _slot, text) in items {
            let got = db.get_tx(id).unwrap().expect("raw tx retrievable by hash");
            let (rendered, hex) = raw_payload_repr(&got.raw_payload);
            assert_eq!(rendered.as_deref(), Some(text), "content shown as UTF-8 text");
            assert_eq!(hex, hex::encode(text.as_bytes()), "hex dump available too");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rc5_live_zone_program_ids_recognized() {
        // Program ids key on the canonical LITTLE-ENDIAN byte form (== the decoder's
        // `program_id_hex`, `getProgramIds`, and the wallet). All three are the live zone's
        // real ids: clock is the EMPIRICAL id read from a settled block (`884e693a…`, NOT
        // the source-tree `e23158e6…`); auth/vault are the zone's natives (wallet-verified).
        let clock = "884e693a302d57de1ac4c405ca5bea1df707d1de11d9f87de51b78845aa98e63";
        let auth = "d9a19237236822b1f8100576ebd19a19f74178f99e284c983a4ac44acbd5b472";
        let vault = "a8d1ec6d803dfc54a55d3cf576388a7d461b02a38bd4cd87ebf30837a2f1df07";
        // clock recognized => skip_clock drops the ~91% clock rows
        assert!(is_clock_program(clock), "live rc5 clock must be recognized for skip_clock");
        // all three resolve to rc5 => the "Sequencer version" tag shows rc5
        assert_eq!(lez_version(clock), Some("rc5"));
        assert_eq!(lez_version(auth), Some("rc5"));
        assert_eq!(lez_version(vault), Some("rc5"));
        // and resolve to human names (program_name_map merges RC5_PROGRAMS)
        let name = |id: &str| RC5_PROGRAMS.iter().find(|(p, _)| *p == id).map(|(_, n)| *n);
        assert_eq!(name(clock), Some("clock"));
        assert_eq!(name(auth), Some("authenticated_transfer"));
        assert_eq!(name(vault), Some("vault"));
        // the deployed clock (LE) is NOT the word-order (BE) form the decoder used to emit
        assert_ne!(clock, "3a694e88de572d3005c4c41a1dea5bcaded107f77df8d91184781be5638ea95a");
        // an unrelated id is neither a clock nor a known LEZ version
        assert!(!is_clock_program(&"ab".repeat(32)));
        assert_eq!(lez_version(&"ab".repeat(32)), None);
    }

    /// End-to-end for the server-side guess pipeline: `build_reference_profiles` learns
    /// `validity_window` from the txs of an id we already name (`df89eefa…`), and then
    /// `classify` must NOT paste that label onto a DIFFERENT unnamed program (`53f7e0f8…`)
    /// that merely shares its 7-account / 68-word shape - it must key on instruction content.
    #[test]
    fn guess_pipeline_breaks_validity_window_shape_collision() {
        use classify::{Kind, Sample};
        let s = |words: Vec<u32>| Sample::new(Kind::Public, 7, words);
        // named: df89eefa = validity_window, instr [3, 15, 30, 45, 60, 0…] padded to 68 words.
        let vw_id = "df89eefa733d4e4b26ec2094b593c1a719a7ff99885f5a4f69c4a9e89a888d05".to_string();
        let mut vw_words = vec![3u32, 15, 30, 45, 60];
        vw_words.resize(68, 0);
        let vw_samples: Vec<Sample> = (0..12).map(|_| s(vw_words.clone())).collect();

        // unknown 53f7e0f8: SAME shape (7 accts / 68 words) but a single big value at word 0
        // (transfer-like content), NOT the [3, bounds…] window signature.
        let x_id = "53f7e0f8000000000000000000000000000000000000000000000000000000aa".to_string();
        let mut x_words = vec![1_000_000u32];
        x_words.resize(68, 0);
        let x_samples: Vec<Sample> = (0..6).map(|_| s(x_words.clone())).collect();

        // a genuinely auth_transfer-shaped unknown (2 accts / 4-word u128 amount).
        let a_id = "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab111".to_string();
        let a_samples: Vec<Sample> =
            (0..4).map(|_| Sample::new(Kind::Public, 2, vec![250, 0, 0, 0])).collect();

        let samples = vec![
            (vw_id.clone(), vw_samples),
            (x_id.clone(), x_samples.clone()),
            (a_id.clone(), a_samples.clone()),
        ];
        let mut names = HashMap::new();
        names.insert(vw_id, "validity_window".to_string());

        let refs = build_reference_profiles(&samples, &names);

        // the collision program must NOT be labeled validity_window on shape alone.
        let gx = classify::classify(&x_samples, &refs);
        assert!(
            gx.as_ref().map_or(true, |g| g.name != "validity_window"),
            "shape-collision wrongly labeled validity_window: {gx:?}"
        );
        // a real validity_window-content tx still resolves to validity_window.
        let mut vw2 = vec![3u32, 12, 24, 36, 48];
        vw2.resize(68, 0);
        let vw2_samples: Vec<Sample> = (0..6).map(|_| s(vw2.clone())).collect();
        assert_eq!(
            classify::classify(&vw2_samples, &refs).map(|g| g.name),
            Some("validity_window".to_string())
        );
        // the auth-shaped unknown resolves (from the SOURCE profile) to authenticated_transfer.
        assert_eq!(
            classify::classify(&a_samples, &refs).map(|g| g.name),
            Some("authenticated_transfer".to_string())
        );
    }

    fn blk(id: u64, hash: &str, prev: &str, ok: bool) -> Decoded {
        Decoded {
            block_id: id,
            hash: hash.into(),
            prev_hash: prev.into(),
            hash_ok: ok,
            ..Default::default()
        }
    }

    #[test]
    fn pending_activity_flags_l1_only_channel_above_lib() {
        // L1-only channel (no seq_tip) whose settlement tip is above finality => pending.
        let mut t = SeqTrack { seq_tip: None, l1_tip_slot: Some(187085), ..Default::default() };
        assert!(has_pending_activity(&t, Some(186706)), "tip>lib on an L1-only channel");

        // unindexed but active: nothing indexed yet, tip moved past its start slot.
        let u = SeqTrack {
            seq_tip: None,
            l1_tip_slot: Some(187085),
            l1_tip_start_slot: Some(187036),
            inscriptions_seen: 0,
            ..Default::default()
        };
        assert!(has_pending_activity(&u, Some(999999)), "active tip, nothing indexed");

        // RPC-indexed channel (seq_tip set, e.g. 8888) is never flagged - its blocks show.
        t.seq_tip = Some(1099);
        assert!(!has_pending_activity(&t, Some(186706)), "RPC channel content is shown");

        // L1-only channel fully caught up (tip <= lib, some indexed) => not pending.
        let done = SeqTrack {
            seq_tip: None,
            l1_tip_slot: Some(186000),
            inscriptions_seen: 12,
            ..Default::default()
        };
        assert!(!has_pending_activity(&done, Some(186706)), "tip<=lib, indexed => quiet");
    }

    #[test]
    fn activity_state_distinguishes_finalizing_clock_and_raw() {
        // finalizing: L1-only channel whose settlement tip is above finality.
        let fin = SeqTrack { seq_tip: None, l1_tip_slot: Some(200), ..Default::default() };
        assert_eq!(activity_state(&fin, Some(100)), Some("finalizing"));

        // raw (guest f8aab825): finalized non-block raw inscriptions, no decodable user tx.
        let und = SeqTrack {
            seq_tip: None,
            l1_tip_slot: Some(50),
            inscriptions_seen: 3,
            saw_undecodable: true,
            ..Default::default()
        };
        assert_eq!(activity_state(&und, Some(100)), Some("raw"));

        // clock-only (82010101): finalized, decodes cleanly, only clock heartbeats.
        let clk = SeqTrack {
            seq_tip: Some(958),
            l1_tip_slot: Some(50),
            inscriptions_seen: 958,
            ..Default::default()
        };
        assert_eq!(activity_state(&clk, Some(100)), Some("clock-only"));

        // user txs present => the table has content => no panel.
        let usr =
            SeqTrack { inscriptions_seen: 5, user_tx_seen: true, saw_undecodable: true, ..Default::default() };
        assert_eq!(activity_state(&usr, Some(100)), None);
    }

    #[test]
    fn verify_chain_clean() {
        // 1 -> 2 -> 3 with correctly linked parent hashes verifies clean.
        let chain = [
            blk(1, "h1", "h0", true),
            blk(2, "h2", "h1", true),
            blk(3, "h3", "h2", true),
        ];
        let c = verify_chain(chain.iter());
        assert_eq!(c.checked, 3);
        assert!(c.ok());
    }

    #[test]
    fn verify_chain_flags_break_gap_and_hash() {
        // parent link broken between 2 and 3 (prev != "h2")
        let broken = [blk(1, "h1", "h0", true), blk(2, "h2", "h1", true), blk(3, "h3", "BAD", true)];
        assert_eq!(verify_chain(broken.iter()).chain_breaks, 1);

        // non-contiguous block ids (2 missing) is an id gap, not a chain break
        let gapped = [blk(1, "h1", "h0", true), blk(3, "h3", "h2", true)];
        let g = verify_chain(gapped.iter());
        assert_eq!(g.id_gaps, 1);
        assert_eq!(g.chain_breaks, 0);

        // a header hash that doesn't recompute is a hash failure
        assert_eq!(verify_chain([blk(1, "h1", "h0", false)].iter()).hash_failures, 1);
    }

    #[test]
    fn verify_chain_light_build_not_verified() {
        // empty hashes (light build) => nothing checked, verdict is "not verified".
        let light = [blk(1, "", "", true), blk(2, "", "", true)];
        assert_eq!(verify_chain(light.iter()).checked, 0);
    }

    #[test]
    fn b58_matches_known_clock_account() {
        // confirmed live: b"/LEZ/ClockProgramAccount/0000001" base58 == this id.
        assert_eq!(
            b58encode(b"/LEZ/ClockProgramAccount/0000001"),
            "4BdcjoXkq786TMWcBGGHqcxeLYMZmn17rL4eM9ZyRWNU"
        );
    }

    #[test]
    fn token_definition_parses_real_layout() {
        // real on-chain TokenDefinition::Fungible{name:"MEDUSA", total_supply:1000}
        let mut data = vec![0u8, 6, 0, 0, 0];
        data.extend_from_slice(b"MEDUSA");
        data.extend_from_slice(&1000u128.to_le_bytes());
        data.push(0); // metadata_id Option<AccountId> = None
        let (name, kind, supply) = parse_token_definition(&data).unwrap();
        assert_eq!(name, "MEDUSA");
        assert_eq!(kind, "fungible");
        assert_eq!(supply, 1000);
    }

    #[test]
    fn token_holding_parses_definition_and_balance() {
        let mut data = vec![0u8];
        data.extend_from_slice(&[7u8; 32]);
        data.extend_from_slice(&950u128.to_le_bytes());
        let (def, bal, kind) = parse_token_holding(&data).unwrap();
        assert_eq!(bal, 950);
        assert_eq!(kind, "fungible");
        assert_eq!(def, b58encode(&[7u8; 32]));
    }

    #[test]
    fn block_id_of_handles_v02_inline_and_v01_flat() {
        // v0.2.0 nests the id at block.header.id (and inlines the whole block).
        let v02 = serde_json::json!({"block":{"header":{"id":"ABcd","slot":5}},"tip":"x"});
        assert_eq!(block_id_of(&v02).as_deref(), Some("abcd"));
        // 0.1.2 carried a top-level block_id.
        let v01 = serde_json::json!({"block_id":"ABcd"});
        assert_eq!(block_id_of(&v01).as_deref(), Some("abcd"));
        // neither present => None (so handle_event skips the fetch).
        assert_eq!(block_id_of(&serde_json::json!({"tip_slot":1})), None);
    }
}
