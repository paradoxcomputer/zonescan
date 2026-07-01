//! `zone-scan` - a sequencer-agnostic L1 observer for LEZ sequencers.
//!
//! Each LEZ sequencer settles to the Logos L1 by posting one `ChannelInscribe`
//! op per L2 block to its own *channel*. That makes the L1 a single, trustless
//! vantage point onto every sequencer settling to it: a sequencer cannot lie to
//! L1 about what it settled, and cannot hide a settled block from a reader.
//!
//! Point the tool at one L1 node and give it one or more channel ids (or let it
//! discover them); it analyzes each sequencer separately from public on-chain
//! data. Modes:
//!
//!   * **watch** (default): poll `/cryptarchia/info` + `/channel/:id`.
//!   * **scan** (`--scan-back N`): one-shot enumeration of every channel's
//!     latest block id + cadence by decoding inscriptions.
//!   * **serve** (`--serve`): a live web dashboard, fed by *streaming* the L1's
//!     `/cryptarchia/events/blocks/stream` and decoding each new block.
//!
//! tx-type mix (Public / PrivacyPreserving / ProgramDeployment) needs decoding
//! the inscribed `Block` body and is gated behind the `decode` feature; the
//! lightweight default still reports block id, L2 timestamp and tx count from a
//! fixed-offset read of the inscription.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use clap::Parser;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

mod serve;

/// Known sequencer channel-id aliases (see README). Node URL is still required:
/// each environment settles to a different L1 node, and low channel ids are
/// reused across environments - so an alias is a convenience, not an identity.
pub const ALIASES: &[(&str, &str)] = &[
    ("dev", "0101010101010101010101010101010101010101010101010101010101010101"),
    ("tg-dev", "0101010101010101010101010101010101010101010101010101010101010101"),
    ("rc4", "0202020202020202020202020202020202020202020202020202020202020202"),
    ("psychopomp", "4242424242424242424242424242424242424242424242424242424242424242"),
];

/// Display aliases: a sequencer channel id -> a friendly name shown in the UI as the
/// primary label (the raw hex stays as the secondary/short form). Distinct from
/// `ALIASES` above (which maps a typed name -> a channel id for CLI input). Extend by
/// adding `(channel_hex, "Display Name")` pairs.
pub const CHANNEL_ALIASES: &[(&str, &str)] = &[(
    "0101010101010101010101010101010101010101010101010101010101010101",
    "Paradox Computer",
)];

/// Friendly display name for a channel id, if one is known; else `None` (callers keep
/// the existing short-hex rendering). Accepts an optional `0x` prefix and any case.
pub fn channel_alias(channel: &str) -> Option<&'static str> {
    let hex = channel.trim_start_matches("0x").to_ascii_lowercase();
    CHANNEL_ALIASES
        .iter()
        .find(|(id, _)| *id == hex)
        .map(|(_, name)| *name)
}

#[derive(Parser, Debug)]
#[command(
    name = "zone-scan",
    about = "Sequencer-agnostic L1 observer for LEZ sequencers (CLI + web dashboard)"
)]
struct Args {
    /// Base URL of the L1 (Logos) node, e.g. http://localhost:8080. Optional for
    /// the web server (configure it in /admin); required for --scan-back/--watch.
    #[arg(long)]
    node: Option<String>,

    /// Sequencer channel(s): a 64-char hex id or a known alias, repeatable and
    /// comma-separated. In watch/serve these are seeded sequencers; in scan they
    /// filter the enumeration (omit to enumerate everything).
    #[arg(long)]
    channel: Vec<String>,

    /// Scan this many finalized slots back from `lib` and add every channel
    /// found to the watch/serve set (auto-discovery).
    #[arg(long)]
    discover: Option<u64>,

    /// Backfill every configured channel's entire settled history (back to
    /// genesis) into the durable store, instead of only the discover window.
    #[arg(long)]
    full_history: bool,

    /// Poll interval in seconds for watch mode (0 = run once and exit).
    #[arg(long, default_value_t = 5)]
    interval: u64,

    /// Switch to scan mode: walk this many finalized slots back from `lib`,
    /// decoding every channel's latest block_id + cadence.
    #[arg(long)]
    scan_back: Option<u64>,

    /// Slots per `/cryptarchia/blocks` request in scan/discover mode.
    #[arg(long, default_value_t = 800)]
    chunk: u64,

    /// Serve the live web dashboard (this is the default mode).
    #[arg(long)]
    serve: bool,

    /// Run the CLI watch mode instead of the web server.
    #[arg(long)]
    watch: bool,

    /// Config file path ($ZONE_SCAN_CONFIG, else <data dir>/config.json).
    #[arg(long)]
    config: Option<String>,

    /// Port for the web dashboard ($ZONE_SCAN_PORT).
    #[arg(long, default_value_t = 8088)]
    port: u16,

    /// Address to bind the web dashboard to ($ZONE_SCAN_HOST). Use 0.0.0.0 in a container.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Optional SOCKS5 proxy for reaching .onion nodes, e.g. 127.0.0.1:9250
    /// (the medusa-bundled Tor). Names are resolved through the proxy.
    #[arg(long)]
    socks5: Option<String>,

    /// Emit JSON instead of the human-readable output (watch/scan).
    #[arg(long)]
    json: bool,
}

/// Minimal `.env` loader: `KEY=VALUE` lines (optional `export `, `#` comments, quoted
/// values). Never overrides a variable already set in the real environment.
fn load_dotenv(path: &std::path::Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        if k.is_empty() || std::env::var_os(k).is_some() {
            continue; // real env wins
        }
        let mut v = v.trim();
        if v.len() >= 2
            && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
        {
            v = &v[1..v.len() - 1];
        }
        std::env::set_var(k, v);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Headless config: load a .env (CWD then the data dir) so ZONE_SCAN_* vars can come
    // from a file. Real environment variables always win (load_dotenv never overrides).
    load_dotenv(std::path::Path::new(".env"));
    load_dotenv(&serve::default_data_dir().join(".env"));
    let args = Args::parse();
    // env overrides the bind defaults (the headless/.env path; CLI is for ad-hoc use)
    let host = std::env::var("ZONE_SCAN_HOST")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| args.host.clone());
    let port = std::env::var("ZONE_SCAN_PORT")
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(args.port);

    // The web server is the DEFAULT mode (the packaged app). It does not require
    // --node; configuration is done in /admin and persisted to a config file.
    // CLI flags, if given, seed that config. --scan-back / --watch select the
    // one-shot CLI modes instead.
    let serve_mode = args.serve || (args.scan_back.is_none() && !args.watch);
    if serve_mode {
        let config_path = args
            .config
            .clone()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(serve::default_config_path);
        let seed = args.node.as_deref().map(|node| serve::Config {
            l1_node_url: node.to_string(),
            socks5: args.socks5.clone(),
            discover_slots: args.discover,
            full_history: args.full_history,
            sequencers: args
                .channel
                .iter()
                .flat_map(|c| c.split(','))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|c| serve::SeqCfg {
                    label: String::new(),
                    channel_id: c.to_string(),
                    rpc_url: String::new(),
                    full: false,
                    discovered: false,
                })
                .collect(),
            program_names: Vec::new(),
            program_schemas: Vec::new(),
            skip_clock: false,
            discover_limit: None,
        });
        return serve::cmd_serve(&host, port, config_path, seed).await;
    }

    // CLI modes (scan / watch) require an explicit node.
    let base = args
        .node
        .as_deref()
        .context("--node is required for --scan-back / --watch")?
        .trim_end_matches('/')
        .to_string();
    let client = build_client(args.socks5.as_deref(), Some(Duration::from_secs(60)), None)?;
    let channels: Vec<String> = args
        .channel
        .iter()
        .flat_map(|c| c.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(resolve_channel)
        .collect::<Result<_>>()?;

    if let Some(back) = args.scan_back {
        let filter: Option<BTreeSet<String>> =
            (!channels.is_empty()).then(|| channels.into_iter().collect());
        let (map, _recs, lib_slot, lo) =
            scan_channels(&client, &base, filter.as_ref(), back, args.chunk, !args.json).await?;
        print_scan_report(&map, lib_slot, lo, back, args.json);
        return Ok(());
    }

    let mut set: BTreeSet<String> = channels.into_iter().collect();
    if let Some(d) = args.discover {
        let (found, _recs, _, _) = scan_channels(&client, &base, None, d, args.chunk, !args.json).await?;
        if !args.json {
            eprintln!(
                "discovered {} channel(s) active in the last {d} slots: {}",
                found.len(),
                found.keys().map(|k| short(k)).collect::<Vec<_>>().join(", ")
            );
        }
        set.extend(found.into_keys());
    }
    if set.is_empty() {
        bail!("watch mode needs at least one --channel <id|alias> or --discover <slots>");
    }
    cmd_watch(&client, &base, set.into_iter().collect(), args.interval, args.json).await
}

// ---------------------------------------------------------------------------
// watch mode
// ---------------------------------------------------------------------------

async fn cmd_watch(
    client: &Client,
    base: &str,
    channels: Vec<String>,
    interval: u64,
    json: bool,
) -> Result<()> {
    let info_url = format!("{base}/cryptarchia/info");
    if !json {
        eprintln!("zone-scan watch: node={base}");
        for c in &channels {
            eprintln!("  sequencer {c}");
        }
        eprintln!("watching each channel's tip vs the L1 finality boundary; Ctrl-C to stop\n");
    }

    let mut l1_prev_slot: Option<u64> = None;
    let mut prev_tips: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut polls: u64 = 0;

    loop {
        polls += 1;
        let info = get_json(client, &info_url).await;
        let (height, slot, lib_slot) = match &info {
            EndpointResult::Ok(v) => (
                info_u64(v, "height"),
                info_u64(v, "slot"),
                info_u64(v, "lib_slot"),
            ),
            _ => (None, None, None),
        };
        let advancing = match (slot, l1_prev_slot) {
            (Some(s), Some(p)) => Some(s > p),
            _ => None,
        };

        let mut rows = Vec::with_capacity(channels.len());
        for ch in &channels {
            let res = get_json(client, &format!("{base}/channel/{ch}")).await;
            let tip = match &res {
                EndpointResult::Ok(v) => Some(channel_tip(v)),
                _ => None,
            };
            let moved = tip.as_ref().and_then(|t| prev_tips.get(ch).map(|p| p != t));
            rows.push((ch.clone(), res, tip, moved));
        }

        if json {
            let chans: Vec<Value> = rows
                .iter()
                .map(|(ch, res, tip, moved)| {
                    json!({"channel": ch, "tip": tip, "moved": moved, "endpoint": endpoint_json(res)})
                })
                .collect();
            println!(
                "{}",
                json!({"ts": chrono::Utc::now().to_rfc3339(), "poll": polls,
                       "l1": {"height": height, "slot": slot, "lib_slot": lib_slot, "advancing": advancing},
                       "channels": chans})
            );
        } else {
            println!(
                "{}",
                render_watch_human(&info, height, slot, lib_slot, advancing, &rows)
            );
        }

        if let Some(s) = slot {
            l1_prev_slot = Some(s);
        }
        for (ch, _, tip, _) in &rows {
            if let Some(t) = tip {
                prev_tips.insert(ch.clone(), t.clone());
            }
        }

        if interval == 0 {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {}
            _ = tokio::signal::ctrl_c() => { if !json { eprintln!("\nstopped."); } break; }
        }
    }
    Ok(())
}

type Row = (String, EndpointResult, Option<String>, Option<bool>);

fn render_watch_human(
    info: &EndpointResult,
    height: Option<u64>,
    slot: Option<u64>,
    lib_slot: Option<u64>,
    advancing: Option<bool>,
    rows: &[Row],
) -> String {
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let l1_line = if matches!(info, EndpointResult::Ok(_)) {
        let lag = match (slot, lib_slot) {
            (Some(s), Some(l)) => format!("finality lag {} slots", s.saturating_sub(l)),
            _ => "finality lag n/a".to_string(),
        };
        let adv = match advancing {
            Some(true) => " ADVANCING",
            Some(false) => " NOT ADVANCING",
            None => "",
        };
        format!("L1: height={} slot={} lib_slot={} ({lag}){adv}", opt(height), opt(slot), opt(lib_slot))
    } else {
        "L1: UNREACHABLE".to_string()
    };

    let mut out = format!("[{ts}]\n  {l1_line}");
    for (ch, res, tip, moved) in rows {
        let (tip_disp, status) = match res {
            EndpointResult::Unreachable(e) => ("?".to_string(), format!("UNREACHABLE ({e})")),
            EndpointResult::Status(s) => ("-".to_string(), format!("NO SETTLEMENT YET (HTTP {s})")),
            EndpointResult::Ok(_) => {
                let t = tip.clone().unwrap_or_else(|| "?".to_string());
                let status = match moved {
                    None => "baseline".to_string(),
                    Some(true) => "ALIVE - settled new block(s)".to_string(),
                    Some(false) => match advancing {
                        Some(true) => "NOT SETTLING (idle or stalled)".to_string(),
                        Some(false) => "idle - L1 not advancing".to_string(),
                        None => "idle".to_string(),
                    },
                };
                let mark = match moved {
                    Some(true) => " (moved)",
                    Some(false) => " (unchanged)",
                    None => "",
                };
                (format!("{}{mark}", short(&t)), status)
            }
        };
        out.push_str(&format!("\n  {}  tip={tip_disp}  {status}", short(ch)));
    }
    out
}

// ---------------------------------------------------------------------------
// scan mode
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Agg {
    pub latest_block_id: u64,
    pub min_block_id: u64,
    pub count: u64,
    pub latest_slot: Option<u64>,
    pub min_slot: Option<u64>,
    /// tx_count / tx_mix of the latest (highest block_id) inscription seen.
    pub tx_count: u32,
    pub tx_mix: Option<TxMix>,
    inited: bool,
}

impl Agg {
    fn update(&mut self, d: &Decoded, slot: Option<u64>) {
        if !self.inited {
            self.latest_block_id = d.block_id;
            self.min_block_id = d.block_id;
            self.inited = true;
        }
        if d.block_id >= self.latest_block_id {
            self.tx_count = d.tx_count;
            self.tx_mix = d.tx_mix.clone();
        }
        self.latest_block_id = self.latest_block_id.max(d.block_id);
        self.min_block_id = self.min_block_id.min(d.block_id);
        self.count += 1;
        if let Some(s) = slot {
            self.latest_slot = Some(self.latest_slot.map_or(s, |x| x.max(s)));
            self.min_slot = Some(self.min_slot.map_or(s, |x| x.min(s)));
        }
    }
}

/// One decoded inscription with its on-chain context (for seeding the tx feed).
pub struct ScanRec {
    pub channel: String,
    pub slot: Option<u64>,
    pub decoded: Decoded,
}

/// Walk finalized blocks back `back_slots` from `lib`, returning per-channel
/// aggregates plus every decoded inscription.
/// Returns `(channels, records, lib_slot, scanned_from_slot)`.
pub async fn scan_channels(
    client: &Client,
    base: &str,
    filter: Option<&BTreeSet<String>>,
    back_slots: u64,
    chunk: u64,
    verbose: bool,
) -> Result<(BTreeMap<String, Agg>, Vec<ScanRec>, u64, u64)> {
    let info = get_json(client, &format!("{base}/cryptarchia/info")).await;
    let lib_slot = match &info {
        EndpointResult::Ok(v) => info_u64(v, "lib_slot").context("no lib_slot in /cryptarchia/info")?,
        EndpointResult::Status(s) => bail!("L1 /cryptarchia/info returned HTTP {s}"),
        EndpointResult::Unreachable(e) => bail!("cannot reach L1 node: {e}"),
    };
    let lo = lib_slot.saturating_sub(back_slots);
    if verbose {
        eprintln!("scanning finalized blocks slots {lo}..={lib_slot} (chunk {chunk})");
    }

    let mut chans: BTreeMap<String, Agg> = BTreeMap::new();
    let mut recs: Vec<ScanRec> = Vec::new();
    let mut l1_blocks = 0u64;
    let mut inscriptions = 0u64;
    let mut hi = lib_slot;
    let chunk = chunk.max(1);

    loop {
        let from = hi.saturating_sub(chunk).max(lo);
        let url = format!("{base}/cryptarchia/blocks?slot_from={from}&slot_to={hi}");
        if let EndpointResult::Ok(Value::Array(blocks)) = get_json(client, &url).await {
            for b in &blocks {
                l1_blocks += 1;
                let slot = b.get("header").and_then(|h| jget_u64(h, "slot")).or_else(|| find_u64(b, "slot"));
                let mut found = Vec::new();
                collect_inscriptions(b, &mut found);
                for (cid, ins) in found {
                    if let Some(f) = filter {
                        if !f.contains(&cid) {
                            continue;
                        }
                    }
                    if let Some(d) = decode_inscription(&ins) {
                        inscriptions += 1;
                        recs.push(ScanRec {
                            channel: cid.clone(),
                            slot,
                            decoded: d.clone(),
                        });
                        chans.entry(cid).or_default().update(&d, slot);
                    }
                }
            }
        }
        if verbose {
            eprint!(
                "\r  down to slot {from}: {l1_blocks} L1 blocks, {} channels, {inscriptions} inscriptions    ",
                chans.len()
            );
        }
        if from <= lo {
            break;
        }
        hi = from.saturating_sub(1);
    }
    if verbose {
        eprintln!("\n");
    }
    Ok((chans, recs, lib_slot, lo))
}

fn print_scan_report(chans: &BTreeMap<String, Agg>, lib_slot: u64, lo: u64, back: u64, json: bool) {
    if json {
        let obj: serde_json::Map<String, Value> = chans
            .iter()
            .map(|(cid, a)| {
                (
                    cid.clone(),
                    json!({"latest_block_id": a.latest_block_id, "min_block_id": a.min_block_id,
                           "inscriptions_seen": a.count, "min_slot": a.min_slot, "latest_slot": a.latest_slot,
                           "cadence_per_1000_slots": cadence(a),
                           "latest_tx_count": a.tx_count, "latest_tx_mix": a.tx_mix}),
                )
            })
            .collect();
        println!("{}", json!({"lib_slot": lib_slot, "scanned_from_slot": lo, "channels": obj}));
        return;
    }
    if chans.is_empty() {
        println!("no channel inscriptions found in the scanned window - every sequencer settling here has been idle for >{back} slots.");
        return;
    }
    println!("channels settling to this L1 (latest in the scanned window; all finalized, <= lib_slot {lib_slot}):\n");
    let mut ordered: Vec<_> = chans.iter().collect();
    ordered.sort_by(|a, b| b.1.count.cmp(&a.1.count));
    for (cid, a) in ordered {
        println!("  channel {}", short(cid));
        println!(
            "    latest block_id = {}   (saw {}..{}, {} inscriptions)",
            a.latest_block_id, a.min_block_id, a.latest_block_id, a.count
        );
        let cad = cadence(a).map_or_else(
            || "n/a (single sample)".to_string(),
            |c| format!("{c:.2} L2 blocks / 1000 L1 slots"),
        );
        println!("    L1 slots {}..{}   cadence {cad}", opt(a.min_slot), opt(a.latest_slot));
        if a.tx_count > 0 || a.tx_mix.is_some() {
            let mix = a.tx_mix.as_ref().map_or_else(
                || " (tx-mix: build with --features decode)".to_string(),
                |m| format!(" [public {} / private {} / deploy {}]", m.public, m.private, m.deploy),
            );
            println!("    latest block: {} tx{mix}", a.tx_count);
        }
    }
}

fn cadence(a: &Agg) -> Option<f64> {
    match (a.min_slot, a.latest_slot) {
        (Some(lo), Some(hi)) if hi > lo => Some(a.count as f64 / (hi - lo) as f64 * 1000.0),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// inscription decoding
// ---------------------------------------------------------------------------

/// Per-block tx-type counts (only populated with `--features decode`).
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TxMix {
    pub public: u32,
    pub private: u32,
    pub deploy: u32,
}

/// A public account's post-state as carried on-chain by a tx (id + balance).
#[derive(Clone, Default, serde::Serialize)]
pub struct AcctState {
    pub id: String,
    pub balance: String,
}

/// One decoded transaction (only populated with `--features decode`). Carries the
/// public, on-chain-visible fields; the privacy boundary keeps amounts and
/// linkage encrypted, so private txs expose only opaque nullifier/commitment
/// digests and the public accounts they touch.
#[derive(Clone, Default, serde::Serialize)]
pub struct TxInfo {
    pub hash: String,
    pub kind: String, // public | private | deploy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nullifiers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub commitments: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_outputs: Option<usize>,
    /// Public-account post-states carried by the tx (the L1-native balance source).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub post_states: Vec<AcctState>,
    /// Raw program instruction words (risc0-serialized) for public txs; decoded
    /// per-program in the UI (e.g. token `Transfer` → amount + from/to).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instruction_data: Vec<u32>,
    /// Operation subtype for privacy-preserving txs: shield / deshield / private-send,
    /// inferred from the nullifier/public-account shape (rc4 carries no explicit op tag).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subtype: String,
    /// For ProgramDeployment txs: the program id (image id) the deployed ELF produces.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub deploy_program: String,
    /// For ProgramDeployment txs: the deployed guest ELF bytes (persisted separately,
    /// served for download; never serialized into the tx feed).
    #[serde(default, skip_serializing)]
    pub deploy_bytecode: Vec<u8>,
}

/// What we can pull out of one inscription (= `borsh(common::Block)`).
#[derive(Clone, Default, serde::Serialize)]
pub struct Decoded {
    pub block_id: u64,
    pub timestamp: u64,
    pub tx_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_mix: Option<TxMix>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub txs: Vec<TxInfo>,
    /// Block hash (hex) as stated in the inscribed header; empty in the light build.
    pub hash: String,
    /// Parent block hash (hex) the header links to; empty in the light build.
    pub prev_hash: String,
    /// Whether the stated header hash matches a recompute of the block contents
    /// (tamper-evidence). `true` when not checked (light build).
    pub hash_ok: bool,
    /// L1 finality: `true` when the sequencer marked this block `bedrock_status = Finalized`
    /// (inscribed to L1 + confirmed beyond lib_slot). Only set in the decode build; `false`
    /// otherwise. Drives the per-sequencer `finalized_block_id` threshold.
    #[serde(default)]
    pub bedrock_final: bool,
}

/// Raw bytes of an inscription value (array-of-numbers or hex string).
fn inscription_bytes(ins: &Value) -> Option<Vec<u8>> {
    match ins {
        Value::Array(a) => a
            .iter()
            .map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect(),
        Value::String(s) => hex::decode(s.trim_start_matches("0x")).ok(),
        _ => None,
    }
}

/// Decode an inscription. The Borsh `common::Block` header is a fixed 144 bytes
/// (block_id u64 + 2×[u8;32] + timestamp u64 + signature [u8;64]), so block_id
/// (offset 0), timestamp (offset 72) and tx_count (Vec len u32 at offset 144)
/// are read without a full decode. The Public/Private/Deploy split needs the
/// real `decode` feature.
pub fn decode_inscription(ins: &Value) -> Option<Decoded> {
    let bytes = inscription_bytes(ins)?;
    if bytes.len() < 8 {
        return None;
    }
    let block_id = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let timestamp = (bytes.len() >= 80)
        .then(|| u64::from_le_bytes(bytes[72..80].try_into().unwrap()))
        .unwrap_or(0);
    let tx_count = (bytes.len() >= 148)
        .then(|| u32::from_le_bytes(bytes[144..148].try_into().unwrap()))
        .unwrap_or(0);
    let (tx_mix, txs, chk, bedrock_final) = decode_block_detail(&bytes);
    let (hash, prev_hash, hash_ok) = chk.unwrap_or_else(|| (String::new(), String::new(), true));
    Some(Decoded {
        block_id,
        timestamp,
        tx_count,
        tx_mix,
        txs,
        hash,
        prev_hash,
        hash_ok,
        bedrock_final,
    })
}

/// Returns `(tx_mix, txs, Some((header_hash_hex, prev_hash_hex, hash_matches_recompute)),
/// bedrock_finalized)`.
#[cfg(feature = "decode")]
fn decode_block_detail(
    bytes: &[u8],
) -> (Option<TxMix>, Vec<TxInfo>, Option<(String, String, bool)>, bool) {
    use common::transaction::NSSATransaction as T;
    use borsh::BorshDeserialize;
    // The linked build is rc4, whose Block = header + body + bedrock_status + a trailing
    // bedrock_parent_id ([u8;32]). rc5 dropped that trailing field (it isn't part of the
    // hashed data - HashableBlockData covers only header + transactions). So read the
    // fields that exist via a reader and default the optional trailing id; rc3/rc4/rc5
    // (whose header + transaction layouts are identical) all decode.
    let block = {
        let mut rdr: &[u8] = bytes;
        let parsed = (|| -> Option<common::block::Block> {
            let header = common::block::BlockHeader::deserialize_reader(&mut rdr).ok()?;
            let body = common::block::BlockBody::deserialize_reader(&mut rdr).ok()?;
            let bedrock_status = common::block::BedrockStatus::deserialize_reader(&mut rdr).ok()?;
            let bedrock_parent_id = <[u8; 32]>::deserialize_reader(&mut rdr).unwrap_or_default();
            Some(common::block::Block { header, body, bedrock_status, bedrock_parent_id })
        })();
        match parsed {
            Some(b) => b,
            None => return (None, vec![], None, false),
        }
    };
    let bedrock_final = matches!(block.bedrock_status, common::block::BedrockStatus::Finalized);
    let mut mix = TxMix::default();
    let txs = block
        .body
        .transactions
        .iter()
        .map(|t| match t {
            T::Public(p) => {
                mix.public += 1;
                TxInfo {
                    hash: hex::encode(p.hash()),
                    kind: "public".into(),
                    program: Some(program_label(&p.message.program_id)),
                    accounts: p.message.account_ids.iter().map(|a| format!("{a:?}")).collect(),
                    instruction_data: p.message.instruction_data.clone(),
                    ..Default::default()
                }
            }
            T::PrivacyPreserving(pp) => {
                mix.private += 1;
                // shield vs deshield isn't in the tx (the amount is ZK-hidden in the
                // witness); it's the *direction* of the public account's balance, resolved
                // later by relabel_privacy() from the balance delta. Tentative here: no
                // public account => private send; otherwise default to shield (the first
                // public-touching op must be a deposit), refined once a prior balance is known.
                let subtype = if pp.message.public_account_ids.is_empty() {
                    "private-send"
                } else {
                    "shield"
                };
                TxInfo {
                    hash: hex::encode(pp.hash()),
                    kind: "private".into(),
                    subtype: subtype.into(),
                    accounts: pp.message.public_account_ids.iter().map(|a| format!("{a:?}")).collect(),
                    nullifiers: pp.message.new_nullifiers.iter().map(|(n, _)| format!("{n:?}")).collect(),
                    commitments: pp.message.new_commitments.iter().map(|c| format!("{c:?}")).collect(),
                    encrypted_outputs: Some(pp.message.encrypted_private_post_states.len()),
                    post_states: pp
                        .message
                        .public_account_ids
                        .iter()
                        .zip(pp.message.public_post_states.iter())
                        .map(|(id, acc)| AcctState {
                            id: format!("{id:?}"),
                            balance: acc.balance.to_string(),
                        })
                        .collect(),
                    ..Default::default()
                }
            }
            T::ProgramDeployment(d) => {
                mix.deploy += 1;
                // the deployment carries the full guest ELF; the deployed program id
                // is the risc0 image id of that ELF (computed, not stated on-chain).
                let bytecode = d.clone().into_message().into_bytecode();
                let deploy_program = nssa::program::Program::new(bytecode.clone())
                    .ok()
                    .map(|p| program_id_hex(&p.id()))
                    .unwrap_or_default();
                TxInfo {
                    hash: hex::encode(d.hash()),
                    kind: "deploy".into(),
                    deploy_program,
                    deploy_bytecode: bytecode,
                    ..Default::default()
                }
            }
        })
        .collect();
    // Tamper-evidence: recompute the block hash exactly as the sequencer (lez-rc4)
    // does - SHA256(b"/LEE/v0.3/Message/Block/" + 8 nul bytes + borsh(HashableBlockData))
    // - since its OwnHasher is private. This couples us to the sequencer's build.
    let hash_ok = {
        use sha2::{Digest, Sha256};
        const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Block/\x00\x00\x00\x00\x00\x00\x00\x00";
        let data = borsh::to_vec(&common::block::HashableBlockData::from(block.clone()))
            .unwrap_or_default();
        let mut bytes = Vec::with_capacity(PREFIX.len() + data.len());
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(&data);
        let computed: [u8; 32] = Sha256::digest(&bytes).into();
        computed == block.header.hash.0
    };
    let hash = hex::encode(block.header.hash.0);
    let prev_hash = hex::encode(block.header.prev_block_hash.0);
    (Some(mix), txs, Some((hash, prev_hash, hash_ok)), bedrock_final)
}

#[cfg(not(feature = "decode"))]
fn decode_block_detail(
    _bytes: &[u8],
) -> (Option<TxMix>, Vec<TxInfo>, Option<(String, String, bool)>, bool) {
    (None, vec![], None, false)
}

/// Canonical on-chain program-id hex: the `[u32; 8]` image id serialized as little-endian
/// bytes (the sequencer `getProgramIds` / wallet / on-chain convention), e.g. the clock's
/// `[0x3a694e88, ..]` -> `"884e693a.."`. NOT the `{w:08x}` word-order form (which reverses
/// each 4-byte group and so never matched the registry / other tools).
pub fn program_id_hex(pid: &[u32; 8]) -> String {
    pid.iter().flat_map(|w| w.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}

/// Human label for a program id: a known built-in name, else a short hex of the id.
#[cfg(feature = "decode")]
fn program_label(pid: &[u32; 8]) -> String {
    use nssa::program::Program;
    use std::collections::HashMap;
    use std::sync::OnceLock;
    static MAP: OnceLock<HashMap<[u32; 8], &'static str>> = OnceLock::new();
    let map = MAP.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(Program::authenticated_transfer_program().id(), "authenticated_transfer");
        m.insert(Program::token().id(), "token");
        m.insert(Program::amm().id(), "amm");
        m.insert(Program::clock().id(), "clock");
        m.insert(Program::ata().id(), "ata");
        m.insert(Program::pinata().id(), "pinata");
        m.insert(Program::pinata_token().id(), "pinata_token");
        m
    });
    map.get(pid).map_or_else(
        || program_id_hex(pid),
        |name| (*name).to_string(),
    )
}

/// The built-in program ids (hex) -> name, computed from our (rc4) build. Lets the
/// server name programs without a reachable sequencer `getProgramIds` RPC, and resolve
/// ids stored as raw hex by an older build (e.g. the clock `625e7b…`).
#[cfg(feature = "decode")]
pub fn builtin_program_ids() -> Vec<(String, String)> {
    use nssa::program::Program;
    let hex = |id: [u32; 8]| program_id_hex(&id);
    vec![
        (hex(Program::authenticated_transfer_program().id()), "authenticated_transfer".into()),
        (hex(Program::token().id()), "token".into()),
        (hex(Program::amm().id()), "amm".into()),
        (hex(Program::clock().id()), "clock".into()),
        (hex(Program::ata().id()), "ata".into()),
        (hex(Program::pinata().id()), "pinata".into()),
        (hex(Program::pinata_token().id()), "pinata_token".into()),
    ]
}

#[cfg(not(feature = "decode"))]
pub fn builtin_program_ids() -> Vec<(String, String)> {
    Vec::new()
}

/// Recursively collect `(channel_id_hex, inscription_value)` pairs.
pub fn collect_inscriptions(v: &Value, out: &mut Vec<(String, Value)>) {
    match v {
        Value::Object(o) => {
            if let (Some(cid), Some(ins)) = (o.get("channel_id"), o.get("inscription")) {
                out.push((jhex(cid), ins.clone()));
            }
            for child in o.values() {
                collect_inscriptions(child, out);
            }
        }
        Value::Array(a) => {
            for child in a {
                collect_inscriptions(child, out);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// shared HTTP
// ---------------------------------------------------------------------------

pub enum EndpointResult {
    Ok(Value),
    Status(StatusCode),
    Unreachable(String),
}

pub async fn get_json(client: &Client, url: &str) -> EndpointResult {
    match client.get(url).send().await {
        Err(e) => EndpointResult::Unreachable(trim_err(&e.to_string())),
        Ok(resp) => decode_resp(resp).await,
    }
}

async fn decode_resp(resp: reqwest::Response) -> EndpointResult {
    let status = resp.status();
    if !status.is_success() {
        return EndpointResult::Status(status);
    }
    match resp.text().await {
        Ok(body) => match serde_json::from_str::<Value>(&body) {
            Ok(v) => EndpointResult::Ok(v),
            Err(_) => EndpointResult::Ok(Value::String(body)),
        },
        Err(e) => EndpointResult::Unreachable(trim_err(&e.to_string())),
    }
}

/// Build an HTTP client. `total_timeout` should be set for normal request/response
/// calls, but left `None` for long-lived streaming connections (the blocks feed).
pub fn build_client(
    socks5: Option<&str>,
    total_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
) -> Result<Client> {
    let mut builder = Client::builder().connect_timeout(Duration::from_secs(30));
    if let Some(t) = total_timeout {
        builder = builder.timeout(t);
    }
    if let Some(t) = read_timeout {
        // for the long-lived blocks stream: if no bytes arrive for this long,
        // drop the (likely-stalled, Tor) connection so the loop reconnects.
        builder = builder.read_timeout(t);
    }
    if let Some(proxy) = socks5 {
        let proxy = reqwest::Proxy::all(format!("socks5h://{proxy}"))
            .context("invalid --socks5 proxy address")?;
        builder = builder.proxy(proxy);
    }
    builder.build().context("failed to build HTTP client")
}

fn endpoint_json(e: &EndpointResult) -> Value {
    match e {
        EndpointResult::Ok(v) => json!({"ok": true, "body": v}),
        EndpointResult::Status(s) => json!({"ok": false, "status": s.as_u16()}),
        EndpointResult::Unreachable(m) => json!({"ok": false, "error": m}),
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

pub fn resolve_channel(input: &str) -> Result<String> {
    if let Some((_, hex)) = ALIASES.iter().find(|(name, _)| *name == input) {
        return Ok((*hex).to_string());
    }
    let lower = input.trim_start_matches("0x").to_ascii_lowercase();
    if lower.len() != 64 || !lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "channel must be a 64-char hex id or a known alias ({}); got {input:?}",
            ALIASES.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
        );
    }
    Ok(lower)
}

pub fn jget_u64(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(coerce_u64)
}

pub fn find_u64(v: &Value, key: &str) -> Option<u64> {
    match v {
        Value::Object(o) => {
            if let Some(found) = o.get(key).and_then(coerce_u64) {
                return Some(found);
            }
            o.values().find_map(|c| find_u64(c, key))
        }
        Value::Array(a) => a.iter().find_map(|c| find_u64(c, key)),
        _ => None,
    }
}

fn coerce_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        Value::Array(a) => a.first().and_then(coerce_u64),
        Value::Object(o) => o.values().next().and_then(coerce_u64),
        _ => None,
    }
}

pub fn jhex(v: &Value) -> String {
    match v {
        Value::String(s) => s.trim_start_matches("0x").to_ascii_lowercase(),
        Value::Array(a) => {
            let bytes: Option<Vec<u8>> = a
                .iter()
                .map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            bytes.map_or_else(|| v.to_string(), hex::encode)
        }
        Value::Null => "?".to_string(),
        other => other.to_string(),
    }
}

/// Read a `/cryptarchia/info` numeric field across node versions. v0.2.0 wraps the
/// fields in a `cryptarchia_info` object (`{cryptarchia_info:{...}, mode}`); 0.1.2
/// returned them flat. Try nested, then flat, then a recursive search.
pub fn info_u64(v: &Value, key: &str) -> Option<u64> {
    v.get("cryptarchia_info")
        .and_then(|i| jget_u64(i, key))
        .or_else(|| jget_u64(v, key))
        .or_else(|| find_u64(v, key))
}

/// Normalize `/cryptarchia/info`'s v0.2.0 `mode` field to a short tag: "online"
/// (fully synced), "bootstrapping" (IBD), or "awaiting" (not started). None on a
/// 0.1.2 node (no `mode` field).
pub fn info_mode(v: &Value) -> Option<String> {
    match v.get("mode")? {
        Value::String(s) if s == "AwaitingStart" => Some("awaiting".into()),
        Value::Object(o) => o
            .get("Started")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase),
        other => Some(other.to_string().trim_matches('"').to_ascii_lowercase()),
    }
}

/// Detect the L1 node's REST API version family from a `/cryptarchia/info` response.
/// v0.2.x wraps the fields in a nested `cryptarchia_info` object and/or carries a `mode`
/// field; 0.1.x returned them flat (`{lib,lib_slot,tip,slot,height}`) with no `mode`.
/// Pure + version-agnostic: defaults to "0.1.x" for the flat/legacy shape.
pub fn info_l1_version(v: &Value) -> &'static str {
    let nested = v.get("cryptarchia_info").is_some_and(Value::is_object);
    if nested || v.get("mode").is_some() {
        "0.2.x"
    } else {
        "0.1.x"
    }
}

/// The settlement (inscription) tip of a `/channel/:id` response, as hex. v0.2.0
/// renamed `tip` -> `tip_message`; accept either. Returns `""` when neither key is
/// present, so a tip-less response reads as "no settlement" (not a spurious change).
pub fn channel_tip(v: &Value) -> String {
    v.get("tip_message")
        .or_else(|| v.get("tip"))
        .filter(|t| !t.is_null()) // an explicit null reads as "no settlement", not "?"
        .map(jhex)
        .unwrap_or_default()
}

pub fn short(s: &str) -> String {
    if s.len() > 14 {
        format!("{}…{}", &s[..8], &s[s.len() - 4..])
    } else {
        s.to_string()
    }
}

fn opt(v: Option<u64>) -> String {
    v.map_or_else(|| "?".to_string(), |n| n.to_string())
}

fn trim_err(s: &str) -> String {
    let one = s.replace('\n', " ");
    if one.len() > 80 {
        format!("{}…", &one[..80])
    } else {
        one
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_resolves() {
        assert_eq!(resolve_channel("dev").unwrap(), "01".repeat(32));
        assert_eq!(resolve_channel("rc4").unwrap(), "02".repeat(32));
    }

    #[test]
    fn raw_hex_normalizes() {
        let id = "AB".repeat(32);
        assert_eq!(resolve_channel(&id).unwrap(), "ab".repeat(32));
        assert_eq!(resolve_channel(&format!("0x{id}")).unwrap(), "ab".repeat(32));
    }

    #[test]
    fn bad_channel_rejected() {
        assert!(resolve_channel("nope").is_err());
        assert!(resolve_channel("ab").is_err());
        assert!(resolve_channel(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn coerce_u64_forms() {
        assert_eq!(coerce_u64(&json!(42)), Some(42));
        assert_eq!(coerce_u64(&json!("42")), Some(42));
        assert_eq!(coerce_u64(&json!([42])), Some(42));
        assert_eq!(coerce_u64(&json!({"slot": 42})), Some(42));
        assert_eq!(coerce_u64(&json!(true)), None);
    }

    // --- v0.2.0 node API compatibility -------------------------------------

    #[test]
    fn info_u64_reads_v02_nested_and_v01_flat() {
        // v0.2.0 wraps the fields in `cryptarchia_info`.
        let v02 = json!({
            "cryptarchia_info": {"lib":"ab","lib_slot":40,"tip":"cd","slot":42,"height":7},
            "mode": {"Started":"Online"}
        });
        assert_eq!(info_u64(&v02, "height"), Some(7));
        assert_eq!(info_u64(&v02, "slot"), Some(42));
        assert_eq!(info_u64(&v02, "lib_slot"), Some(40));
        // 0.1.2 returned them flat.
        let v01 = json!({"lib_slot":40,"slot":42,"height":7});
        assert_eq!(info_u64(&v01, "height"), Some(7));
        assert_eq!(info_u64(&v01, "lib_slot"), Some(40));
    }

    #[test]
    fn info_mode_normalizes_sync_state() {
        assert_eq!(info_mode(&json!({"mode":{"Started":"Online"}})).as_deref(), Some("online"));
        assert_eq!(
            info_mode(&json!({"mode":{"Started":"Bootstrapping"}})).as_deref(),
            Some("bootstrapping")
        );
        assert_eq!(info_mode(&json!({"mode":"AwaitingStart"})).as_deref(), Some("awaiting"));
        // 0.1.2 has no `mode` field.
        assert_eq!(info_mode(&json!({"height":1})), None);
    }

    #[test]
    fn channel_tip_accepts_both_field_names() {
        assert_eq!(channel_tip(&json!({"tip_message":"ABcd"})), "abcd"); // v0.2.0
        assert_eq!(channel_tip(&json!({"tip":"ABcd"})), "abcd"); // 0.1.2
        // tip_message wins when both somehow present
        assert_eq!(channel_tip(&json!({"tip_message":"aa","tip":"bb"})), "aa");
        // missing OR explicit-null => empty (refresh_channels: "no settlement")
        assert_eq!(channel_tip(&json!({"balance":0})), "");
        assert_eq!(channel_tip(&json!({"tip_message": Value::Null})), "");
    }

    #[test]
    fn info_l1_version_detects_v01_flat_and_v02_nested() {
        // v0.2.x: nested `cryptarchia_info` object and/or a `mode` field.
        let v02 = json!({
            "cryptarchia_info": {"lib":"ab","lib_slot":40,"tip":"cd","slot":42,"height":7},
            "mode": {"Started":"Online"}
        });
        assert_eq!(info_l1_version(&v02), "0.2.x");
        // the `mode` field alone (any shape) is enough to detect v0.2.x.
        assert_eq!(info_l1_version(&json!({"mode":"AwaitingStart"})), "0.2.x");
        // 0.1.x: flat fields, no wrapper, no `mode` => the legacy default.
        let v01 = json!({"lib":"ab","lib_slot":40,"tip":"cd","slot":42,"height":7});
        assert_eq!(info_l1_version(&v01), "0.1.x");
    }

    #[test]
    fn channel_alias_known_and_unknown() {
        let paradox = "0101010101010101010101010101010101010101010101010101010101010101";
        // known id -> friendly name (accepts a 0x prefix / any case)
        assert_eq!(channel_alias(paradox), Some("Paradox Computer"));
        assert_eq!(channel_alias(&format!("0x{}", paradox.to_uppercase())), Some("Paradox Computer"));
        // unknown id -> None (caller keeps the short-hex rendering)
        assert_eq!(channel_alias(&"ab".repeat(32)), None);
    }

    #[test]
    fn program_id_hex_is_little_endian_bytes() {
        // The live clock's image-id words (as the decoder reads them from a settled block's
        // Message.program_id) -> canonical on-chain LE-byte hex `884e693a…` (== getProgramIds
        // / the wallet). NOT the old `{w:08x}` word form `3a694e88…`.
        let clock = [
            0x3a694e88u32, 0xde572d30, 0x05c4c41a, 0x1dea5bca, 0xded107f7, 0x7df8d911, 0x84781be5,
            0x638ea95a,
        ];
        assert_eq!(
            program_id_hex(&clock),
            "884e693a302d57de1ac4c405ca5bea1df707d1de11d9f87de51b78845aa98e63"
        );
        // authenticated_transfer word0 = 0x3792a1d9 -> LE bytes "d9a19237.."
        assert!(program_id_hex(&[0x3792a1d9, 0, 0, 0, 0, 0, 0, 0]).starts_with("d9a19237"));
    }

    #[test]
    fn decode_inscription_offsets() {
        // 148+ byte buffer: block_id=48 @0, timestamp=1000 @72, tx_count=3 @144
        let mut b = vec![0u8; 148];
        b[0..8].copy_from_slice(&48u64.to_le_bytes());
        b[72..80].copy_from_slice(&1000u64.to_le_bytes());
        b[144..148].copy_from_slice(&3u32.to_le_bytes());
        let arr: Vec<Value> = b.iter().map(|n| json!(n)).collect();
        let d = decode_inscription(&Value::Array(arr)).unwrap();
        assert_eq!(d.block_id, 48);
        assert_eq!(d.timestamp, 1000);
        assert_eq!(d.tx_count, 3);
    }

    #[test]
    fn collect_inscriptions_finds_nested() {
        let block = json!({
            "header": {"slot": 6072278},
            "transactions": [{"mantle_tx": {"ops": [
                {"ChannelInscribe": {"channel_id": "0101", "inscription": [48,0,0,0,0,0,0,0]}}
            ]}}]
        });
        let mut out = Vec::new();
        collect_inscriptions(&block, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "0101");
        assert_eq!(decode_inscription(&out[0].1).unwrap().block_id, 48);
    }

    #[test]
    fn collect_inscriptions_v02_opcode_payload_hex_shape() {
        // v0.2 block: transactions[].mantle_tx.ops[] carry a tagged op
        // {opcode:17, payload:{channel_id, inscription}} where the inscription is now a
        // HEX STRING (0.1.x used an int array). The same recursive walk must find it and
        // decode it, so the serve/CLI ingest ingests channel `0101…01`'s blocks.
        let mut buf = vec![0u8; 148];
        buf[0..8].copy_from_slice(&42u64.to_le_bytes()); // block_id @0
        buf[144..148].copy_from_slice(&3u32.to_le_bytes()); // tx_count @144
        let ins_hex = hex::encode(&buf);
        let channel = "0101010101010101010101010101010101010101010101010101010101010101";
        let block = json!({
            "header": {"id": "abcd", "slot": 66997},
            "transactions": [{"mantle_tx": {"hash": "ff", "ops": [
                {"opcode": 17, "payload": {
                    "channel_id": channel,
                    "inscription": ins_hex,
                    "parent": "00",
                    "signer": "00"
                }}
            ]}}]
        });
        let mut out = Vec::new();
        collect_inscriptions(&block, &mut out);
        assert_eq!(out.len(), 1, "one inscription collected from the v0.2 shape");
        assert_eq!(out[0].0, channel);
        let d = decode_inscription(&out[0].1).expect("v0.2 hex-string inscription decodes");
        assert_eq!(d.block_id, 42);
        assert_eq!(d.tx_count, 3);
    }

    // rc5 dropped the trailing `bedrock_parent_id` ([u8;32]) from Block; its header +
    // transaction layouts are identical to rc4. A block whose trailing 32 bytes are
    // stripped (the rc5 shape) must still recover the txs + the same hash verdict.
    #[cfg(feature = "decode")]
    #[test]
    fn decodes_rc4_and_rc5_block_shapes() {
        let txs = vec![
            common::test_utils::produce_dummy_empty_transaction(),
            common::test_utils::produce_dummy_empty_transaction(),
        ];
        let block = common::test_utils::produce_dummy_block(7, Some(common::HashType([1; 32])), txs);
        let full = borsh::to_vec(&block).unwrap(); // rc4 shape (trailing bedrock_parent_id present)

        let (mix4, txs4, chk4, _f4) = decode_block_detail(&full);
        assert!(mix4.is_some() && chk4.is_some() && !txs4.is_empty(), "rc4-shaped block decodes");

        let rc5 = &full[..full.len() - 32]; // strip the trailing bedrock_parent_id (the rc5 shape)
        let (mix5, txs5, chk5, _f5) = decode_block_detail(rc5);
        assert!(mix5.is_some(), "rc5-shaped block (trailing field dropped) still decodes");
        // full (rc4) and stripped (rc5) must recover the identical transactions + hash verdict
        assert_eq!(txs5.len(), txs4.len(), "same transactions recovered");
        assert_eq!(txs5[0].hash, txs4[0].hash, "same first tx hash");
        assert_eq!(chk5.unwrap().2, chk4.unwrap().2, "same hash verdict (bedrock_parent_id isn't hashed)");
    }

    // A real settled clock block from the netcup L1 (rc5). Its single tx is the clock
    // invocation; decode must surface program_id as the canonical LE-byte form
    // `884e693a…` (== on-chain / getProgramIds), NOT the old `{w:08x}` word form.
    #[cfg(feature = "decode")]
    #[test]
    fn decodes_live_rc5_clock_program_id_as_le_bytes() {
        let fixture = "a205000000000000c397231c0f850a31916dc58702b1e10d434d1c8626905aa462bac626d2705621931180c4e7eac93beaa51ec66ff8f11a413c876b02f5bba161e7300c457353e66f3fc11d9f0100009df1300f0f147dd0e518116563d052d157901f1fbaab01f5293712eeb3b829399e67037055062e92dde94ce714b713a7db0db6458b0231189fc3f2dbcc1d8e620100000000884e693a302d57de1ac4c405ca5bea1df707d1de11d9f87de51b78845aa98e63030000002f4c455a2f436c6f636b50726f6772616d4163636f756e742f303030303030312f4c455a2f436c6f636b50726f6772616d4163636f756e742f303030303031302f4c455a2f436c6f636b50726f6772616d4163636f756e742f3030303030353000000000020000006f3fc11d9f0100000000000000";
        let d = decode_inscription(&Value::String(fixture.into())).expect("rc5 clock block decodes");
        let progs: Vec<Option<String>> = d.txs.iter().map(|t| t.program.clone()).collect();
        assert!(
            d.txs.iter().any(|t| t.program.as_deref()
                == Some("884e693a302d57de1ac4c405ca5bea1df707d1de11d9f87de51b78845aa98e63")),
            "clock program_id must decode to LE 884e693a..; got {progs:?}"
        );
    }
}
