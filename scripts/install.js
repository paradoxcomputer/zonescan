#!/usr/bin/env node
'use strict';

/*
 * postinstall: download a prebuilt zone-scan binary from GitHub Releases.
 *
 * Hard rules (see SHARED CONTRACT):
 *   - Zero npm deps. Built-ins only: https, fs, path, crypto.
 *   - Never break `npm install`: any network / 404 / unsupported-platform
 *     failure logs a friendly note and exits 0 (the launcher will build from
 *     source). The ONLY exit(1) is a verified checksum MISMATCH (corrupt/MITM).
 *   - No interactive prompts, no stdin, HTTPS only.
 *   - Resilient under `npm ci` / CI where the network may be blocked.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Constants / config
// ---------------------------------------------------------------------------

// GitHub repo that hosts the release assets. This is independent of the npm
// package name (which is scoped). Keep in sync with the SHARED CONTRACT.
const GH_REPO = 'paradoxcomputer/zonescan';
const RELEASE_BASE = `https://github.com/${GH_REPO}/releases/download`;

// Cargo [[bin]] name == npm bin command == on-disk binary name.
const BIN_NAME = 'zone-scan';

const REQUEST_TIMEOUT_MS = 30000;
const MAX_RETRIES = 2; // => up to 3 attempts total
const MAX_REDIRECTS = 5;

// Only download (and follow redirects) to GitHub + its release-asset CDN, so a
// hijacked redirect can't point the installer at an arbitrary host.
function hostAllowed(hostname) {
  return (
    hostname === 'github.com' ||
    hostname === 'codeload.github.com' ||
    hostname.endsWith('.githubusercontent.com')
  );
}

// process.platform + process.arch -> rust target triple (exact contract table).
const TARGETS = {
  'linux:x64': 'x86_64-unknown-linux-gnu',
  'linux:arm64': 'aarch64-unknown-linux-gnu',
  'darwin:x64': 'x86_64-apple-darwin',
  'darwin:arm64': 'aarch64-apple-darwin',
  'win32:x64': 'x86_64-pc-windows-msvc',
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function log(msg) {
  console.log(`[zone-scan] ${msg}`);
}
function warn(msg) {
  console.warn(`[zone-scan] ${msg}`);
}

// Read version/name from our own package.json. Fall back gracefully so a
// malformed/renamed package.json never throws here.
function readPkg() {
  try {
    return require('../package.json');
  } catch (_) {
    return {};
  }
}

function getTriple() {
  const key = `${process.platform}:${process.arch}`;
  return TARGETS[key] || null;
}

function isWindows() {
  return process.platform === 'win32';
}

// Where the launcher (bin/zone-scan.js) looks for the binary.
function distPaths(triple) {
  const exe = isWindows() ? `${BIN_NAME}.exe` : BIN_NAME;
  const dir = path.join(__dirname, '..', 'dist', triple);
  return { dir, file: path.join(dir, exe), exe };
}

function assetName(triple, light) {
  // Asset on the release: zone-scan-<triple>[-light][.exe]
  const suffix = light ? '-light' : '';
  return isWindows() ? `${BIN_NAME}-${triple}${suffix}.exe` : `${BIN_NAME}-${triple}${suffix}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// HTTP: download a URL to a Buffer, following redirects. HTTPS only.
// ---------------------------------------------------------------------------

function fetchBuffer(url, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (e) {
      reject(new Error(`bad url: ${url}`));
      return;
    }
    if (parsed.protocol !== 'https:') {
      reject(new Error(`refusing non-https url: ${parsed.protocol}`));
      return;
    }
    if (!hostAllowed(parsed.hostname)) {
      reject(new Error(`refusing untrusted host: ${parsed.hostname}`));
      return;
    }

    const req = https.get(
      url,
      {
        headers: {
          // Some CDNs/GitHub are picky without a UA.
          'User-Agent': 'zone-scan-installer',
          Accept: 'application/octet-stream',
        },
      },
      (res) => {
        const status = res.statusCode || 0;

        // Redirect (GitHub release assets -> CDN).
        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume(); // drain
          if (redirectsLeft <= 0) {
            reject(new Error('too many redirects'));
            return;
          }
          const next = new URL(res.headers.location, url).toString();
          resolve(fetchBuffer(next, redirectsLeft - 1));
          return;
        }

        if (status !== 200) {
          res.resume(); // drain
          const err = new Error(`HTTP ${status} for ${url}`);
          err.statusCode = status;
          reject(err);
          return;
        }

        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      }
    );

    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(`timeout after ${REQUEST_TIMEOUT_MS}ms`));
    });
    req.on('error', reject);
  });
}

// Retry wrapper with linear backoff. A 404 is not retried (asset truly absent).
async function fetchWithRetry(url, { retries = MAX_RETRIES } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fetchBuffer(url);
    } catch (err) {
      lastErr = err;
      if (err && err.statusCode === 404) throw err; // don't retry a hard 404
      if (attempt < retries) {
        const backoff = 500 * (attempt + 1);
        warn(`download attempt ${attempt + 1} failed (${err.message}); retrying in ${backoff}ms`);
        await sleep(backoff);
      }
    }
  }
  throw lastErr;
}

// ---------------------------------------------------------------------------
// checksums.txt parsing
// ---------------------------------------------------------------------------

// Format (sha256sum): "<hex>  zone-scan-<triple>[.exe]" per line.
function parseChecksum(text, asset) {
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // hex, then whitespace (sha256sum uses two spaces / "*"), then filename.
    const m = trimmed.match(/^([a-fA-F0-9]{64})\s+[* ]?(.+)$/);
    if (!m) continue;
    const [, hex, file] = m;
    if (path.basename(file.trim()) === asset) {
      return hex.toLowerCase();
    }
  }
  return null;
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// Download `asset` from the release and verify it against checksums.txt. Returns the
// verified Buffer, or null when the asset/checksum is absent (the caller may try a
// fallback). Throws an error with `.checksumMismatch` ONLY on a hash mismatch
// (corrupt/MITM) - the one case that must fail the install.
async function fetchVerifiedAsset(asset, tag) {
  const binUrl = `${RELEASE_BASE}/${tag}/${asset}`;
  const checksumUrl = `${RELEASE_BASE}/${tag}/checksums.txt`;
  log(`  ${binUrl}`);

  let binBuf;
  try {
    binBuf = await fetchWithRetry(binUrl);
  } catch (err) {
    if (err && err.statusCode === 404) return null; // not on this release (e.g. light-only platform)
    warn(`could not download ${asset} (${err.message}).`);
    return null;
  }

  // Fail CLOSED: install only checksum-verified binaries. A missing checksum entry is
  // anomalous (possible MITM dropping the verification file), so we decline rather than
  // install something unverified.
  let expected = null;
  try {
    const csBuf = await fetchWithRetry(checksumUrl);
    expected = parseChecksum(csBuf.toString('utf8'), asset);
  } catch (err) {
    warn(`could not fetch checksums.txt (${err.message}).`);
  }
  if (!expected) {
    warn(`no verified checksum for ${asset}; refusing to install an unverified binary.`);
    return null;
  }
  const actual = sha256(binBuf);
  if (actual !== expected) {
    const e = new Error(
      `checksum MISMATCH for ${asset}\n  expected ${expected}\n  actual   ${actual}`
    );
    e.checksumMismatch = true;
    throw e;
  }
  log(`checksum verified (${asset}).`);
  return binBuf;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const pkg = readPkg();
  const version = pkg.version || '0.3.0';
  const tag = `v${version}`;

  if (process.env.ZONE_SCAN_SKIP_DOWNLOAD === '1') {
    log('ZONE_SCAN_SKIP_DOWNLOAD=1 set; skipping prebuilt download.');
    return 0;
  }

  // Full per-transaction decoding is the default (we download the full prebuilt below).
  // With ZONE_SCAN_DECODE off the user wants the light binary instead - we download THAT
  // prebuilt directly, so opting out never requires a Rust toolchain. Heavy decoding is
  // opt-in; it's also the automatic fallback target when a platform has no full build.
  const decodeOff = ['0', 'false', 'no', 'off', 'light'].includes(
    (process.env.ZONE_SCAN_DECODE || '').trim().toLowerCase()
  );

  const triple = getTriple();
  if (!triple) {
    log(
      `no prebuilt binary for ${process.platform}/${process.arch}; ` +
        'the launcher will build from source if needed.'
    );
    return 0;
  }

  const { dir, file, exe } = distPaths(triple);

  // Already present? Nothing to do.
  if (fs.existsSync(file)) {
    log(`binary already present at dist/${triple}/${exe}; skipping download.`);
    return 0;
  }

  log(`downloading ${BIN_NAME} ${version} for ${triple}${decodeOff ? ' (light)' : ''}`);

  // Asset selection: light when opted out; otherwise the full (decode) binary, falling
  // back to the light binary if this platform has no full build. A checksum MISMATCH is
  // the only hard failure; a missing asset/checksum just declines (→ launcher builds).
  let binBuf;
  try {
    if (decodeOff) {
      binBuf = await fetchVerifiedAsset(assetName(triple, true), tag);
    } else {
      binBuf = await fetchVerifiedAsset(assetName(triple, false), tag);
      if (!binBuf) {
        log('no full (decode) binary for this platform; falling back to the light binary.');
        binBuf = await fetchVerifiedAsset(assetName(triple, true), tag);
      }
    }
  } catch (err) {
    if (err && err.checksumMismatch) {
      console.error(`[zone-scan] ${err.message}`);
      return 1; // corrupt or tampered download: fail the install
    }
    throw err; // unexpected - the top-level guard turns it into a clean exit
  }

  if (!binBuf) {
    warn('could not download a prebuilt binary; the launcher will build from source if needed.');
    return 0;
  }

  // Write the file atomically-ish: write to a temp name then rename.
  try {
    fs.mkdirSync(dir, { recursive: true });
    const tmp = `${file}.download-${process.pid}`;
    fs.writeFileSync(tmp, binBuf);
    if (!isWindows()) {
      try {
        fs.chmodSync(tmp, 0o755);
      } catch (e) {
        warn(`could not chmod binary (${e.message}); continuing.`);
      }
    }
    fs.renameSync(tmp, file);
  } catch (err) {
    // Filesystem hiccup must not break the install either.
    warn(`could not write binary (${err.message}); the launcher will build from source if needed.`);
    return 0;
  }

  log(`installed prebuilt binary to dist/${triple}/${exe}`);
  return 0;
}

// Top-level guard: nothing escapes to a non-zero exit except an explicit
// checksum mismatch (code 1).
main()
  .then((code) => process.exit(typeof code === 'number' ? code : 0))
  .catch((err) => {
    warn(`unexpected installer error (${err && err.message}); skipping prebuilt download.`);
    process.exit(0);
  });
