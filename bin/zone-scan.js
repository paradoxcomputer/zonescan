#!/usr/bin/env node
'use strict';

// npm "bin" launcher for the zone-scan Rust binary.
// CommonJS, zero npm dependencies.
//
// Resolution order for the binary (see SHARED CONTRACT):
//   1. $ZONE_SCAN_BIN
//   2. dist/<triple>/zone-scan[.exe]
//   3. bin/zone-scan-<triple>[.exe]
//   4. target/release/zone-scan[.exe]
//   5. target/debug/zone-scan[.exe]
//   6. build from source: `cargo build --release --features decode`
//
// Subcommands handled here (argv[2]); the subcommand word is NOT forwarded to
// the binary:
//   setup  -> start server + open the /setup?token=... page (or "/" if already
//             configured via env). Honors ZONE_SCAN_NO_OPEN.
//   start  -> run the server normally, no browser.
//   (other / none) -> run the server and open "/" after ~1.5s unless
//                     ZONE_SCAN_NO_OPEN is set. All args forwarded.

const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// process.platform/process.arch -> Rust target triple (exact contract table).
// ---------------------------------------------------------------------------
const TRIPLES = {
  'linux-x64': 'x86_64-unknown-linux-gnu',
  'linux-arm64': 'aarch64-unknown-linux-gnu',
  'darwin-x64': 'x86_64-apple-darwin',
  'darwin-arm64': 'aarch64-apple-darwin',
  'win32-x64': 'x86_64-pc-windows-msvc',
};

const isWin = process.platform === 'win32';
const exeSuffix = isWin ? '.exe' : '';
const exe = `zone-scan${exeSuffix}`;
const triple = TRIPLES[`${process.platform}-${process.arch}`] || null;

// ---------------------------------------------------------------------------
// Tiny, dependency-free .env reader (CWD only). Used purely to discover
// ZONE_SCAN_PORT / ZONE_SCAN_DATA (and the L1/sequencer hints) for URL
// building. We do NOT export these - the Rust binary loads .env itself.
// ---------------------------------------------------------------------------
function readDotenv() {
  const out = {};
  let text;
  try {
    text = fs.readFileSync(path.join(process.cwd(), '.env'), 'utf8');
  } catch (_) {
    return out;
  }
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('export ')) line = line.slice(7).trim();
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

const dotenv = readDotenv();

// Prefer the real process env, fall back to a value parsed from .env.
function cfg(name) {
  if (process.env[name] != null && process.env[name] !== '') return process.env[name];
  if (dotenv[name] != null && dotenv[name] !== '') return dotenv[name];
  return undefined;
}

// ---------------------------------------------------------------------------
// Binary resolution.
// ---------------------------------------------------------------------------
function candidates() {
  const list = [process.env.ZONE_SCAN_BIN];
  if (triple) {
    list.push(path.join(root, 'dist', triple, exe));
    list.push(path.join(root, 'bin', `zone-scan-${triple}${exeSuffix}`));
  }
  list.push(path.join(root, 'target', 'release', exe));
  list.push(path.join(root, 'target', 'debug', exe));
  return list.filter(Boolean);
}

function findBin() {
  for (const c of candidates()) {
    try {
      if (fs.statSync(c).isFile()) return c;
    } catch (_) {}
  }
  return null;
}

function haveCargo() {
  try {
    const r = spawnSync('cargo', ['--version'], { stdio: 'ignore' });
    return r.status === 0;
  } catch (_) {
    return false;
  }
}

// Whether to build/use the heavy `decode` feature (full per-tx decoding, which pulls the
// logos-blockchain + risc0 stack). Default on; opt out with ZONE_SCAN_DECODE=0/false/light/off
// to build a light binary (block-level data + liveness, no per-tx decode).
function wantsDecode() {
  const v = (cfg('ZONE_SCAN_DECODE') || '').trim().toLowerCase();
  return !['0', 'false', 'no', 'off', 'light'].includes(v);
}

function buildFromSource() {
  if (!fs.existsSync(path.join(root, 'Cargo.toml'))) {
    console.error('zone-scan: no prebuilt binary and no Cargo.toml to build from.');
    console.error('  - point ZONE_SCAN_BIN at a prebuilt zone-scan binary, or');
    console.error('  - reinstall the package so the postinstall can download a binary.');
    process.exit(1);
  }
  if (!haveCargo()) {
    console.error('zone-scan: no prebuilt binary found, and cargo is not installed.');
    console.error('  Install the Rust toolchain to build from source:');
    console.error('    https://rustup.rs');
    console.error('    (Linux/macOS) curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh');
    console.error('  Or set ZONE_SCAN_BIN to a prebuilt zone-scan binary.');
    process.exit(1);
  }
  const runCargo = (features) => {
    const args = ['build', '--release'];
    if (features) args.push('--features', features);
    console.error(`           cargo ${args.join(' ')}\n`);
    return spawnSync('cargo', args, { cwd: root, stdio: 'inherit' }).status;
  };
  const fail = (status) => {
    console.error('\nzone-scan: cargo build failed.');
    process.exit(status == null ? 1 : status);
  };

  if (!wantsDecode()) {
    // User opted out of the heavy decode stack - build a light binary.
    console.error('zone-scan: no prebuilt binary found - building a light binary');
    console.error('           (ZONE_SCAN_DECODE off: block-level data + liveness, no per-tx decode).');
    const status = runCargo(null);
    if (status !== 0) fail(status);
    return path.join(root, 'target', 'release', exe);
  }

  // Default: full transaction decoding. This pulls the logos-blockchain + risc0 stack
  // and can be slow or fail on some platforms - so if it fails, fall back to a light
  // build automatically rather than leaving the user with no binary.
  console.error('zone-scan: no prebuilt binary found - building from source WITH full');
  console.error('           transaction decoding (heavy: pulls the logos-blockchain + risc0');
  console.error('           stack). For a fast, light build set ZONE_SCAN_DECODE=0.');
  let status = runCargo('decode');
  if (status !== 0) {
    console.error('\nzone-scan: the decode build failed - falling back to a light binary');
    console.error('           (block-level data + liveness, no per-tx decode). Set');
    console.error('           ZONE_SCAN_DECODE=0 to choose the light build directly next time.');
    status = runCargo(null);
  }
  if (status !== 0) fail(status);
  return path.join(root, 'target', 'release', exe);
}

// ---------------------------------------------------------------------------
// Data directory resolution (identical to the Rust binary / contract).
// ---------------------------------------------------------------------------
function dataDir() {
  const explicit = cfg('ZONE_SCAN_DATA');
  if (explicit) return explicit;
  if (isWin) {
    const appdata = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    return path.join(appdata, 'zone-scan');
  }
  const xdg = process.env.XDG_CONFIG_HOME;
  if (xdg) return path.join(xdg, 'zone-scan');
  return path.join(os.homedir(), '.config', 'zone-scan');
}

// ---------------------------------------------------------------------------
// Port resolution: ZONE_SCAN_PORT, then --port <n>, then default 8088.
// ---------------------------------------------------------------------------
function resolvePort(args) {
  const i = args.indexOf('--port');
  const raw = cfg('ZONE_SCAN_PORT') || (i >= 0 ? args[i + 1] : '') || '8088';
  // The port flows into a URL we hand to the OS browser opener (e.g. `cmd /c start`
  // on Windows), so accept only 1-5 digits - never arbitrary text.
  return /^[0-9]{1,5}$/.test(String(raw).trim()) ? String(raw).trim() : '8088';
}

// True when a complete env config exists (app is already configured).
function hasEnvConfig() {
  return Boolean(cfg('ZONE_SCAN_L1_NODE_URL') || cfg('ZONE_SCAN_SEQUENCERS'));
}

// ---------------------------------------------------------------------------
// Browser open: cross-platform, detached + unref, never throws.
// ---------------------------------------------------------------------------
function openBrowser(url) {
  if (process.env.ZONE_SCAN_NO_OPEN) return;
  let cmd;
  let cmdArgs;
  if (process.platform === 'darwin') {
    cmd = 'open';
    cmdArgs = [url];
  } else if (isWin) {
    cmd = 'cmd';
    cmdArgs = ['/c', 'start', '', url];
  } else {
    cmd = 'xdg-open';
    cmdArgs = [url];
  }
  try {
    const c = spawn(cmd, cmdArgs, { stdio: 'ignore', detached: true });
    c.on('error', () => {});
    c.unref();
  } catch (_) {}
}

// Poll for <data>/setup-token to appear (server writes it on startup), then
// return its trimmed contents. Gives up after ~timeoutMs and returns null.
function waitForSetupToken(timeoutMs, cb) {
  const tokenPath = path.join(dataDir(), 'setup-token');
  const deadline = Date.now() + timeoutMs;
  const tick = () => {
    try {
      const tok = fs.readFileSync(tokenPath, 'utf8').trim();
      if (tok) return cb(tok);
    } catch (_) {}
    if (Date.now() >= deadline) return cb(null);
    setTimeout(tick, 150);
  };
  tick();
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------
const rawArgs = process.argv.slice(2);
const sub = rawArgs[0];
//   setup  -> foreground + open the token-gated setup page
//   up     -> start in the BACKGROUND (detached), record a pid file
//   down   -> stop the backgrounded server
//   start  -> foreground, no browser
//   (none) -> foreground + open the dashboard
const KNOWN_SUBS = new Set(['setup', 'start', 'up', 'down']);
const isSub = KNOWN_SUBS.has(sub);
// Forward everything except a recognized leading subcommand word.
const args = isSub ? rawArgs.slice(1) : rawArgs;

const port = resolvePort(args);
const base = `http://127.0.0.1:${port}`;
const pidFile = path.join(dataDir(), 'zonescan.pid');
const logFile = path.join(dataDir(), 'zonescan.log');

// `down`: stop a backgrounded server. No binary needed.
if (sub === 'down') {
  let pid = 0;
  try { pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10); } catch (_) {}
  if (!pid) {
    console.error('zonescan: no background server found (no pid file).');
    process.exit(1);
  }
  try {
    process.kill(pid, 'SIGTERM');
    console.log(`zonescan: stopped (pid ${pid}).`);
  } catch (e) {
    if (e.code === 'ESRCH') console.log('zonescan: server was not running (stale pid).');
    else { console.error(`zonescan: could not stop pid ${pid}: ${e.message}`); process.exit(1); }
  }
  try { fs.unlinkSync(pidFile); } catch (_) {}
  process.exit(0);
}

const bin = findBin() || buildFromSource();

// `up`: start detached in the background, record the pid, return immediately.
if (sub === 'up') {
  let out = 'ignore';
  try { fs.mkdirSync(dataDir(), { recursive: true }); out = fs.openSync(logFile, 'a'); } catch (_) {}
  const bg = spawn(bin, args, { detached: true, stdio: ['ignore', out, out] });
  bg.unref();
  try { fs.writeFileSync(pidFile, String(bg.pid)); } catch (_) {}
  console.log(`zonescan: started in background (pid ${bg.pid}) -> ${base}`);
  console.log(`  logs: ${logFile}    stop: zonescan down`);
  process.exit(0);
}

// setup / start / default: run in the foreground.
const child = spawn(bin, args, { stdio: 'inherit' });

if (sub === 'setup') {
  if (hasEnvConfig()) {
    // Already configured by env; just open the dashboard.
    setTimeout(() => openBrowser(`${base}/`), 1500);
  } else {
    waitForSetupToken(5000, (tok) => {
      const url = tok
        ? `${base}/setup?token=${encodeURIComponent(tok)}`
        : `${base}/setup`;
      openBrowser(url);
    });
  }
} else if (sub === 'start') {
  // Run the server normally; no auto-open.
} else {
  // Default: run the server and open the dashboard.
  setTimeout(() => openBrowser(`${base}/`), 1500);
}

child.on('error', (err) => {
  console.error(`zonescan: failed to launch binary: ${err.message}`);
  process.exit(1);
});
child.on('exit', (code, signal) => {
  if (signal) {
    // Re-raise the signal semantics with a conventional 128+signal code.
    process.exit(128 + (os.constants.signals[signal] || 0));
  }
  process.exit(code == null ? 0 : code);
});

function forward(sig) {
  try {
    child.kill(sig);
  } catch (_) {}
}
process.on('SIGINT', () => forward('SIGINT'));
process.on('SIGTERM', () => forward('SIGTERM'));
