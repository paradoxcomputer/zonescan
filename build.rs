//! Captures the build's git revision so the running binary can state exactly which
//! commit it is. Verifying "what is actually deployed?" has repeatedly meant comparing
//! md5sums by hand; a build tag in the UI answers it directly.
//!
//! Degrades to an empty string whenever git can't answer (release tarball, vendored
//! crate, npm package, CI checkout without history). Callers must treat it as optional -
//! it is a convenience, never a correctness input.

use std::process::Command;

fn main() {
    // Re-run triggers. `src` and `Cargo.toml` matter as much as the git files: naming ONLY
    // the git paths opts out of cargo's default "any package file changed" rule, so editing
    // sources without touching `.git` left the previous tag cached — the binary then claims a
    // commit it does not contain, and a dirty tree reports clean. A tag that can lie is worse
    // than no tag. Missing paths are tolerated (a tarball has no `.git`).
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    // `.git/HEAD` only changes when the BRANCH changes — committing (or amending, or
    // squashing) rewrites `.git/refs/heads/<branch>` while HEAD's contents stay
    // `ref: refs/heads/main`. Watching HEAD alone let a squash ship a binary tagged with a
    // commit that no longer existed. `packed-refs` covers the same refs once packed.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    println!("cargo:rustc-env=ZONESCAN_GIT={}", git_describe().unwrap_or_default());
}

/// `<short-hash>` for a clean tree, `<short-hash>-dirty` when tracked files are modified.
/// The dirty marker matters: an operator comparing the UI tag against a commit needs to
/// know the binary contains uncommitted work.
fn git_describe() -> Option<String> {
    let out = Command::new("git").args(["rev-parse", "--short", "HEAD"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let hash = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if hash.is_empty() {
        return None;
    }
    // `--porcelain` prints one line per modified tracked path; empty output = clean.
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .is_some_and(|o| o.status.success() && !o.stdout.is_empty());
    Some(if dirty { format!("{hash}-dirty") } else { hash })
}
