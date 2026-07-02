//! Best-guess program naming by instruction fingerprint.
//!
//! A program's risc0 image id is BUILD-SPECIFIC: a foreign sequencer's
//! `authenticated_transfer` has a different id than ours and so shows up un-named. But the
//! *interface* a program presents on-chain - its account count and the risc0-serialized
//! instruction layout (variant discriminant, field offsets, where a u64/u128 amount sits) -
//! is stable across builds even though the id isn't. We fingerprint that interface and match
//! it against reference profiles to render a clearly-marked guess (`≈ name`).
//!
//! Counts alone are NOT enough: on the live `0101` channel `53f7e0f8` (7 accts / 68 words)
//! is identical in *shape* to `validity_window` (`df89eefa`, 7 accts / 68 words). The
//! classifier therefore weights instruction STRUCTURE (the per-word value classes, the
//! discriminant, the amount offset) over the raw counts, and only surfaces a guess when the
//! best match clears a confidence threshold AND beats the runner-up by a margin - otherwise
//! it honestly reports `unknown`. A low-confidence miss is far better than a confident wrong
//! label.
//!
//! Two reference sources feed the profiles:
//!  1. SOURCE-DERIVED (primary, `source_profiles`): the LEZ program crates' account lists +
//!     instruction enums (token / authenticated_transfer / amm / ata / pinata / clock),
//!     hand-encoded from the `v0.2.0-rc4` guest sources. Stable across builds.
//!  2. RUNTIME-LEARNED (`learn_profile`): aggregated over the txs we CAN already name (the
//!     id->name map, which has several ids per name, plus `getProgramIds`). This both
//!     augments the built-ins and supplies profiles for rebuilt genesis/test programs whose
//!     encodings differ from source (e.g. the deployed `validity_window`).

use std::collections::BTreeMap;

/// How many leading instruction words we keep in a structural pattern. Deep enough to cover
/// every built-in variant (ata Transfer is 13 words; a program-id field is 8) without letting
/// long padded instructions dominate the comparison.
const PAT_CAP: usize = 16;

/// Coarse value-class of one risc0 instruction word. Structural matching keys on these rather
/// than exact values, so an amount of `5` and an amount of `1_000_000` share a signature while
/// a discriminant `3` stays distinct from a big amount.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cls {
    /// Word is exactly 0 - padding, a zero amount, or a zero enum discriminant.
    Zero,
    /// Small value 1..=15 - a plausible enum discriminant / variant tag.
    Tag,
    /// >= 16 - a "big" value: an amount, a hash limb, a program-id limb, a timestamp.
    Big,
    /// Template wildcard: matches any observed class. Never produced from data.
    Any,
}

fn cls(w: u32) -> Cls {
    if w == 0 {
        Cls::Zero
    } else if w <= 15 {
        Cls::Tag
    } else {
        Cls::Big
    }
}

impl Cls {
    /// Does an observed word-class satisfy this (possibly-wildcard) template class?
    fn accepts(self, observed: Cls) -> bool {
        self == Cls::Any || self == observed
    }
}

/// The tx family an invocation belongs to, mirrored from `TxRecord.kind`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Public,
    Private,
    Deploy,
    Other,
}

impl Kind {
    pub fn from_str(s: &str) -> Kind {
        match s {
            "public" => Kind::Public,
            "private" => Kind::Private,
            "deploy" => Kind::Deploy,
            _ => Kind::Other,
        }
    }
}

/// One observed invocation of a program: the account count and the raw risc0 instruction words.
#[derive(Clone, Debug)]
pub struct Sample {
    pub kind: Kind,
    pub accts: u16,
    pub words: Vec<u32>,
}

impl Sample {
    pub fn new(kind: Kind, accts: u16, words: Vec<u32>) -> Sample {
        Sample { kind, accts, words }
    }
}

/// True when `w[off..off+4]` reads as a u128 whose value fits in 64 bits (high two words zero)
/// and whose low word is set - the fingerprint of a realistic amount field at a fixed offset.
/// The low-word requirement is what keeps a token `Transfer` (`[0, amount, 0, 0, 0]`) from
/// spuriously reading an amount at offset 0 - its amount sits at offset 1, after the `0`
/// discriminant.
fn has_u128_at(w: &[u32], off: usize) -> bool {
    if off + 4 > w.len() {
        return false;
    }
    w[off] != 0 && w[off + 2] == 0 && w[off + 3] == 0
}

/// Index one past the last non-`Zero` class - the "significant" length of a pattern, i.e. its
/// leading structure with trailing zero-padding stripped. Structural scoring works over this so
/// a long instruction's zero padding can't manufacture a match.
fn sig_len(pat: &[Cls]) -> usize {
    pat.iter().rposition(|c| *c != Cls::Zero).map_or(0, |i| i + 1)
}

/// True when `(w[off], w[off+1])` reads as a u64 in the millisecond-epoch range
/// (~2017..2049) - the clock-tick / deadline signature.
fn has_ms_ts_at(w: &[u32], off: usize) -> bool {
    if off + 2 > w.len() {
        return false;
    }
    let v = (w[off] as u64) | ((w[off + 1] as u64) << 32);
    (1_500_000_000_000..=2_500_000_000_000).contains(&v)
}

/// The structural features of a single sample, derived once for scoring.
#[derive(Clone, Debug)]
pub struct Feat {
    pub kind: Kind,
    pub accts: u16,
    pub len: u16,
    pub v0: u32,
    /// Per-word value-class of the leading words (capped at `PAT_CAP`). Trailing zero-padding is
    /// handled at match time via the significant-prefix (`sig_len`), so it needs no own field.
    pub pat: Vec<Cls>,
    /// Smallest field-aligned offset (0/1/9) carrying a u128 amount, if any.
    pub amount_off: Option<u16>,
    pub has_ms_ts: bool,
}

impl Feat {
    pub fn of(s: &Sample) -> Feat {
        let pat: Vec<Cls> = s.words.iter().take(PAT_CAP).map(|w| cls(*w)).collect();
        // Amounts live right after a discriminant. Probe the offsets the built-ins actually use:
        // 0 (bare u128: authenticated_transfer / pinata), 1 (token Transfer/Burn/Mint), 9 (ata,
        // after an 8-word program id + 1-word discriminant).
        let amount_off = [0usize, 1, 9]
            .into_iter()
            .find(|o| has_u128_at(&s.words, *o))
            .map(|o| o as u16);
        let has_ms_ts = (0..s.words.len().saturating_sub(1)).any(|o| has_ms_ts_at(&s.words, o));
        Feat {
            kind: s.kind,
            accts: s.accts,
            len: s.words.len() as u16,
            v0: s.words.first().copied().unwrap_or(0),
            pat,
            amount_off,
            has_ms_ts,
        }
    }
}

/// Constraint on an instruction word count.
#[derive(Clone, Debug)]
pub enum LenSpec {
    /// Exactly `n` words (decays with distance so a near-miss still scores partially).
    Exact(u16),
    /// At least `n` words (variable-length instructions, e.g. a trailing String).
    Min(u16),
}

impl LenSpec {
    fn score(&self, len: u16) -> f64 {
        match *self {
            LenSpec::Exact(n) => {
                if len == n {
                    1.0
                } else {
                    let d = (len as i32 - n as i32).unsigned_abs();
                    (1.0 - d as f64 / (n.max(4) as f64)).max(0.0)
                }
            }
            LenSpec::Min(n) => {
                if len >= n {
                    1.0
                } else {
                    (len as f64 / n as f64).max(0.0)
                }
            }
        }
    }
}

/// Constraint on the first instruction word (the enum discriminant, for enum programs).
#[derive(Clone, Debug)]
pub enum V0Spec {
    Exact(u32),
    /// Any first word is acceptable (a bare-scalar instruction, e.g. authenticated_transfer's
    /// leading amount word - it is not a discriminant).
    Any,
}

impl V0Spec {
    fn score(&self, v0: u32) -> f64 {
        match *self {
            V0Spec::Exact(n) => {
                if v0 == n {
                    1.0
                } else {
                    0.0
                }
            }
            V0Spec::Any => 1.0,
        }
    }
}

/// Where a u128 amount is expected within the instruction (for the amount-offset feature).
#[derive(Clone, Copy, Debug)]
pub enum AmountSpec {
    At(u16),
    None,
}

/// One expected instruction variant of a program.
#[derive(Clone, Debug)]
pub struct Template {
    /// Human tag for the variant - documents the template and aids test/Debug output.
    #[allow(dead_code)]
    pub variant: &'static str,
    pub kind: Kind,
    /// Allowed account counts.
    pub accts: Vec<u16>,
    pub len: LenSpec,
    pub v0: V0Spec,
    pub amount: AmountSpec,
    /// Expected leading word-class pattern; compared position-by-position (wildcards allowed).
    pub pat: Vec<Cls>,
    /// Require an ms-epoch timestamp somewhere (clock ticks / deadlines).
    pub want_ts: bool,
}

impl Template {
    /// Score a sample's features against this template, in `[0, 1]`. Structure (discriminant,
    /// per-word pattern, amount offset) is weighted over the raw counts; a wrong account count
    /// is a near-veto so a mere shape collision can't carry a match.
    fn score(&self, f: &Feat) -> f64 {
        let acct_ok = self.accts.iter().any(|a| *a == f.accts);
        let len_s = self.len.score(f.len);
        let v0_s = self.v0.score(f.v0);
        let pat_s = if self.pat.is_empty() {
            1.0
        } else {
            // Compare over the significant prefix of BOTH template and sample, so trailing
            // zero-padding neither pads a match nor is required to match. An empty significant
            // window (both all-zero, e.g. an all-zero "register" instruction) is a full match.
            let n = sig_len(&self.pat).max(sig_len(&f.pat));
            if n == 0 {
                1.0
            } else {
                let hits = (0..n)
                    .filter(|i| {
                        let tc = self.pat.get(*i).copied().unwrap_or(Cls::Zero);
                        let oc = f.pat.get(*i).copied().unwrap_or(Cls::Zero);
                        tc.accepts(oc)
                    })
                    .count();
                hits as f64 / n as f64
            }
        };
        let amt_s = match self.amount {
            AmountSpec::At(o) => {
                if f.amount_off == Some(o) {
                    1.0
                } else {
                    0.3
                }
            }
            AmountSpec::None => 1.0,
        };
        let kind_ok = self.kind == f.kind;
        let ts_s = if self.want_ts {
            if f.has_ms_ts {
                1.0
            } else {
                0.2
            }
        } else {
            1.0
        };

        // Weighted blend. Base term keeps a plausible-but-weak match off zero; structure terms
        // (v0 + pattern + amount) carry the most weight.
        let raw = 0.12
            + 0.18 * len_s
            + 0.20 * v0_s
            + 0.30 * pat_s
            + 0.12 * amt_s
            + 0.08 * ts_s;
        let raw = raw.min(1.0);

        let mut s = raw;
        if !acct_ok {
            s *= 0.20; // wrong account count: cannot win on shape alone.
        }
        if !kind_ok {
            s *= 0.35; // wrong tx family (public vs private/deploy).
        }
        s
    }
}

/// Where a reference profile came from - drives how much we trust it.
#[derive(Clone, Debug)]
pub enum Provenance {
    /// Hand-encoded from the LEZ guest sources: stable interface, fully trusted.
    Source,
    /// Aggregated from `n` on-chain txs we already name. Trust grows with sample count.
    Runtime(u32),
}

impl Provenance {
    fn evidence(&self) -> f64 {
        match *self {
            Provenance::Source => 1.0,
            Provenance::Runtime(n) => (n as f64 / 8.0).clamp(0.25, 1.0),
        }
    }
}

/// A named reference: the templates a program name is expected to present.
#[derive(Clone, Debug)]
pub struct Profile {
    pub name: String,
    pub provenance: Provenance,
    pub templates: Vec<Template>,
}

impl Profile {
    /// Best template score for a single sample-feature.
    fn score_feat(&self, f: &Feat) -> f64 {
        self.templates
            .iter()
            .map(|t| t.score(f))
            .fold(0.0f64, f64::max)
    }
}

/// The surfaced best-guess for an unrecognized program.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Guess {
    pub name: String,
    /// `[0, 1]` overall confidence (match strength x margin x evidence x sample sufficiency).
    pub confidence: f64,
    /// Best raw match score against the winning profile, `[0, 1]`.
    pub score: f64,
    /// Best-minus-runner-up score margin, `[0, 1]`.
    pub margin: f64,
    /// How many of the program's txs fed the fingerprint.
    pub samples: u32,
}

// --- thresholds -------------------------------------------------------------
/// Minimum raw match score for the winning profile.
const MIN_SCORE: f64 = 0.62;
/// Minimum score margin over the runner-up (so a genuine shape-tie stays unknown).
const MIN_MARGIN: f64 = 0.10;
/// Minimum overall confidence to surface a guess at all.
const MIN_CONFIDENCE: f64 = 0.45;

/// Reduce a program's samples to its distinct structural feature-clusters, each with a weight
/// (how many samples fell in it). Distinct instruction variants of the SAME program (e.g. token
/// Transfer vs InitializeAccount) become separate clusters so one rare variant can't drown out
/// the common one, and vice-versa.
fn cluster(samples: &[Sample]) -> Vec<(Feat, u32)> {
    let mut map: BTreeMap<(u16, u16, u32, Vec<u8>), (Feat, u32)> = BTreeMap::new();
    for s in samples {
        let f = Feat::of(s);
        let key = (
            f.accts,
            f.len,
            f.v0,
            f.pat.iter().map(|c| *c as u8).collect::<Vec<u8>>(),
        );
        map.entry(key).or_insert_with(|| (f.clone(), 0)).1 += 1;
    }
    map.into_values().collect()
}

/// Score one program (its clustered features) against one profile: the sample-weighted mean of
/// per-cluster best-template scores.
fn profile_score(clusters: &[(Feat, u32)], profile: &Profile) -> f64 {
    let mut num = 0.0;
    let mut den = 0.0;
    for (f, w) in clusters {
        num += profile.score_feat(f) * (*w as f64);
        den += *w as f64;
    }
    if den == 0.0 {
        0.0
    } else {
        num / den
    }
}

/// Classify an unrecognized program from its own txs against the reference profiles. Returns a
/// `Guess` only when the best match clears the score/margin/confidence thresholds; otherwise
/// `None` ("unknown program"). `references` should be `source_profiles()` plus any runtime
/// profiles learned from named programs.
pub fn classify(samples: &[Sample], references: &[Profile]) -> Option<Guess> {
    if samples.is_empty() || references.is_empty() {
        return None;
    }
    let clusters = cluster(samples);

    // Score every profile; keep the best, and remember the best PER-NAME so several ids/profiles
    // that share a name don't count as each other's runner-up (which would kill the margin).
    let mut scored: Vec<(f64, &Profile)> = references
        .iter()
        .map(|p| (profile_score(&clusters, p), p))
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    let (best_score, best) = scored.first().map(|(s, p)| (*s, *p))?;
    let runner_up = scored
        .iter()
        .find(|(_, p)| p.name != best.name)
        .map(|(s, _)| *s)
        .unwrap_or(0.0);
    let margin = (best_score - runner_up).max(0.0);

    if best_score < MIN_SCORE || margin < MIN_MARGIN {
        return None;
    }

    let n_samples: u32 = clusters.iter().map(|(_, w)| *w).sum();
    let margin_factor = (margin / 0.25).clamp(0.0, 1.0);
    let prog_evidence = (n_samples as f64 / 4.0).clamp(0.4, 1.0);
    let confidence =
        best_score * (0.4 + 0.6 * margin_factor) * best.provenance.evidence() * prog_evidence;

    if confidence < MIN_CONFIDENCE {
        return None;
    }
    Some(Guess {
        name: best.name.clone(),
        confidence: (confidence * 1000.0).round() / 1000.0,
        score: (best_score * 1000.0).round() / 1000.0,
        margin: (margin * 1000.0).round() / 1000.0,
        samples: n_samples,
    })
}

/// Learn a runtime reference profile for a program NAME from the on-chain txs we already
/// attribute to it. Each distinct structural cluster becomes a template pinned to the observed
/// account count, length, discriminant (kept exact only when it's a small tag - a big leading
/// word is a scalar, not a discriminant) and per-word class pattern.
pub fn learn_profile(name: &str, samples: &[Sample]) -> Option<Profile> {
    if samples.is_empty() {
        return None;
    }
    let clusters = cluster(samples);
    let n: u32 = clusters.iter().map(|(_, w)| *w).sum();
    let templates = clusters
        .iter()
        .map(|(f, _)| {
            let v0 = if f.v0 <= 15 {
                V0Spec::Exact(f.v0)
            } else {
                V0Spec::Any
            };
            let amount = match f.amount_off {
                Some(o) => AmountSpec::At(o),
                None => AmountSpec::None,
            };
            Template {
                variant: "learned",
                kind: f.kind,
                accts: vec![f.accts],
                len: LenSpec::Exact(f.len),
                v0,
                amount,
                pat: f.pat.clone(),
                want_ts: f.has_ms_ts,
            }
        })
        .collect();
    Some(Profile {
        name: name.to_string(),
        provenance: Provenance::Runtime(n),
        templates,
    })
}

/// Hand-encoded reference profiles for the stable LEZ built-ins, derived from the `v0.2.0-rc4`
/// guest sources (`programs/*/core/src/lib.rs`, `program_methods/guest/src/bin/*.rs`). These
/// are the PRIMARY reference: their interface (accounts + instruction layout) is identical
/// across builds even though the image id isn't, so a foreign build of any of them fingerprints
/// the same. Amount positions in a pattern are `Big` where the low word is typically set;
/// wildcards (`Any`) cover value-dependent words.
pub fn source_profiles() -> Vec<Profile> {
    use AmountSpec::{At, None as NoAmt};
    use Cls::{Any, Big, Tag, Zero};
    use Kind::Public;
    use LenSpec::{Exact, Min};
    use V0Spec::{Any as AnyV0, Exact as ExV0};

    let mut p = Vec::new();

    // authenticated_transfer: instruction = bare `u128 balance_to_move` (4 words, no
    // discriminant). Transfer touches [sender, recipient] (2 accts); Register/init touches
    // [account] (1 acct) with amount 0 (all-zero instruction).
    p.push(Profile {
        name: "authenticated_transfer".into(),
        provenance: Provenance::Source,
        templates: vec![
            Template {
                variant: "transfer",
                kind: Public,
                accts: vec![2],
                len: Exact(4),
                v0: AnyV0,
                amount: At(0),
                pat: vec![Any, Zero, Zero, Zero],
                want_ts: false,
            },
            Template {
                variant: "register",
                kind: Public,
                accts: vec![1],
                len: Exact(4),
                v0: ExV0(0),
                amount: NoAmt,
                pat: vec![Zero, Zero, Zero, Zero],
                want_ts: false,
            },
        ],
    });

    // token: enum Instruction. Transfer(0){u128}, NewFungibleDefinition(1){String,u128},
    // NewDefinitionWithMetadata(2), InitializeAccount(3), Burn(4){u128}, Mint(5){u128}.
    p.push(Profile {
        name: "token".into(),
        provenance: Provenance::Source,
        templates: vec![
            Template {
                variant: "Transfer",
                kind: Public,
                accts: vec![2],
                len: Exact(5),
                v0: ExV0(0),
                amount: At(1),
                pat: vec![Zero, Big, Zero, Zero, Zero],
                want_ts: false,
            },
            Template {
                variant: "InitializeAccount",
                kind: Public,
                accts: vec![1, 2],
                len: Exact(1),
                v0: ExV0(3),
                amount: NoAmt,
                pat: vec![Tag],
                want_ts: false,
            },
            Template {
                variant: "NewFungibleDefinition",
                kind: Public,
                accts: vec![1, 2],
                len: Min(3),
                v0: ExV0(1),
                amount: NoAmt,
                pat: vec![Tag],
                want_ts: false,
            },
            Template {
                variant: "Burn",
                kind: Public,
                accts: vec![1, 2],
                len: Exact(5),
                v0: ExV0(4),
                amount: At(1),
                pat: vec![Tag, Big, Zero, Zero, Zero],
                want_ts: false,
            },
            Template {
                variant: "Mint",
                kind: Public,
                accts: vec![1, 2],
                len: Exact(5),
                v0: ExV0(5),
                amount: At(1),
                pat: vec![Tag, Big, Zero, Zero, Zero],
                want_ts: false,
            },
        ],
    });

    // amm: enum. NewDefinition(0){2x u128}, AddLiquidity(1){3x u128}, RemoveLiquidity(2){3x
    // u128}, plus swaps. Accounts are pool + token holdings (3..5).
    p.push(Profile {
        name: "amm".into(),
        provenance: Provenance::Source,
        templates: vec![
            Template {
                variant: "NewDefinition",
                kind: Public,
                accts: vec![3, 4, 5],
                len: Exact(9),
                v0: ExV0(0),
                amount: At(1),
                pat: vec![Zero, Big, Zero, Zero, Zero, Big, Zero, Zero, Zero],
                want_ts: false,
            },
            Template {
                variant: "AddLiquidity",
                kind: Public,
                accts: vec![3, 4, 5],
                len: Exact(13),
                v0: ExV0(1),
                amount: At(1),
                // three u128 fields: [disc, a,0,0,0, b,0,0,0, c,0,0,0]
                pat: vec![Tag, Big, Zero, Zero, Zero, Big, Zero, Zero, Zero, Big, Zero, Zero, Zero],
                want_ts: false,
            },
            Template {
                variant: "RemoveLiquidity",
                kind: Public,
                accts: vec![3, 4, 5],
                len: Exact(13),
                v0: ExV0(2),
                amount: At(1),
                pat: vec![Tag, Big, Zero, Zero, Zero, Big, Zero, Zero, Zero, Big, Zero, Zero, Zero],
                want_ts: false,
            },
        ],
    });

    // ata: enum. Create(0){ProgramId=8 words}, Transfer(1){ProgramId, u128}, Burn(2){ProgramId,
    // u128}. The program-id occupies words 1..9, so an amount sits at offset 9.
    p.push(Profile {
        name: "ata".into(),
        provenance: Provenance::Source,
        templates: vec![
            Template {
                variant: "Create",
                kind: Public,
                accts: vec![3, 4, 5],
                len: Exact(9),
                v0: ExV0(0),
                amount: NoAmt,
                pat: vec![Zero, Big, Big, Big, Big],
                want_ts: false,
            },
            Template {
                variant: "Transfer",
                kind: Public,
                accts: vec![3, 4, 5],
                len: Exact(13),
                v0: ExV0(1),
                amount: At(9),
                pat: vec![Tag, Big, Big, Big, Big, Big, Big, Big, Big, Big, Zero, Zero, Zero],
                want_ts: false,
            },
            Template {
                variant: "Burn",
                kind: Public,
                accts: vec![2, 3, 4],
                len: Exact(13),
                v0: ExV0(2),
                amount: At(9),
                pat: vec![Tag, Big, Big, Big, Big, Big, Big, Big, Big, Big, Zero, Zero, Zero],
                want_ts: false,
            },
        ],
    });

    // pinata: instruction = bare `u128` PoW solution (4 words, no discriminant), touching
    // [pinata, winner] (2 accts). A found solution is a wide 128-bit value: require the high
    // words to be populated, which is what separates it from an authenticated_transfer amount
    // (whose high words are zero). A pinata whose solution happens to be small is genuinely
    // ambiguous with a transfer - and correctly resolves at low confidence.
    p.push(Profile {
        name: "pinata".into(),
        provenance: Provenance::Source,
        templates: vec![Template {
            variant: "Claim",
            kind: Public,
            accts: vec![2],
            len: Exact(4),
            v0: AnyV0,
            amount: NoAmt,
            pat: vec![Big, Big, Big, Big],
            want_ts: false,
        }],
    });

    // clock: instruction = `u64` block timestamp (2 words, ms epoch), writing the granularity
    // clock accounts. Recognized by id already, but keep a profile so a foreign clock still
    // fingerprints as one rather than colliding with something else.
    p.push(Profile {
        name: "clock".into(),
        provenance: Provenance::Source,
        templates: vec![Template {
            variant: "Tick",
            kind: Public,
            accts: vec![1, 3],
            len: Exact(2),
            v0: AnyV0,
            amount: NoAmt,
            pat: vec![Big, Any],
            want_ts: true,
        }],
    });

    p
}

#[cfg(test)]
mod tests {
    use super::*;

    /// risc0-serialize a small u128 as 4 little-endian u32 words.
    fn u128w(v: u128) -> Vec<u32> {
        (0..4).map(|i| (v >> (32 * i)) as u32).collect()
    }

    fn refs() -> Vec<Profile> {
        source_profiles()
    }

    #[test]
    fn authenticated_transfer_native_shape_resolves() {
        // [sender, recipient], instruction = u128 amount (small) => [amt, 0, 0, 0].
        let s = vec![
            Sample::new(Kind::Public, 2, u128w(250)),
            Sample::new(Kind::Public, 2, u128w(1_000)),
            Sample::new(Kind::Public, 2, u128w(42)),
        ];
        let g = classify(&s, &refs()).expect("should classify");
        assert_eq!(g.name, "authenticated_transfer");
        assert!(g.confidence > 0.5, "confidence {g:?}");
    }

    #[test]
    fn token_transfer_resolves_and_beats_authenticated() {
        // token Transfer = [0, u128 amount] => 5 words, accts 2.
        let mut w = vec![0u32];
        w.extend(u128w(250));
        let s = vec![Sample::new(Kind::Public, 2, w.clone()); 4];
        let g = classify(&s, &refs()).expect("should classify");
        assert_eq!(g.name, "token", "5-word variant-0 transfer must be token, not auth");
    }

    #[test]
    fn ata_transfer_resolves() {
        // ata Transfer = [1, program_id(8 big words), u128 amount] => 13 words.
        let mut w = vec![1u32];
        w.extend((0..8).map(|i| 0x1000_0000u32 + i)); // program id limbs (big, nonzero)
        w.extend(u128w(500));
        let s = vec![Sample::new(Kind::Public, 4, w); 3];
        let g = classify(&s, &refs()).expect("should classify");
        assert_eq!(g.name, "ata");
    }

    #[test]
    fn clock_tick_resolves() {
        // u64 ms-epoch timestamp, 2 words. ~2026.
        let ts: u64 = 1_780_000_000_000;
        let w = vec![ts as u32, (ts >> 32) as u32];
        let s = vec![Sample::new(Kind::Public, 3, w); 5];
        let g = classify(&s, &refs()).expect("should classify");
        assert_eq!(g.name, "clock");
    }

    /// THE tie-break the task calls out: `53f7e0f8` (7 accts / 68 words) has the exact SAME
    /// shape as the deployed `validity_window` (`df89eefa`), but different instruction content.
    /// It must NOT be labeled validity_window on shape alone.
    fn validity_window_runtime_profile() -> Profile {
        // learned from df89eefa: instr [3, 15, 30, 45, 60, 0...] padded to 68 words, 7 accts.
        let mut w = vec![3u32, 15, 30, 45, 60];
        w.resize(68, 0);
        let s = vec![Sample::new(Kind::Public, 7, w); 12];
        learn_profile("validity_window", &s).unwrap()
    }

    #[test]
    fn validity_window_matches_its_own_content() {
        let mut refs = refs();
        refs.push(validity_window_runtime_profile());
        // a fresh df89eefa-shaped tx (variant 3, increasing window bounds).
        let mut w = vec![3u32, 12, 24, 36, 48];
        w.resize(68, 0);
        let s = vec![Sample::new(Kind::Public, 7, w); 6];
        let g = classify(&s, &refs).expect("validity_window content should classify");
        assert_eq!(g.name, "validity_window");
    }

    #[test]
    fn same_shape_different_content_is_not_validity_window() {
        // 7 accts / 68 words - IDENTICAL shape to validity_window - but the instruction is a
        // single big value at word 0 (transfer-like), NOT the [3, bounds...] window pattern.
        let mut refs = refs();
        refs.push(validity_window_runtime_profile());
        let mut w = vec![1_000_000u32]; // big value, not the discriminant 3
        w.resize(68, 0);
        let s = vec![Sample::new(Kind::Public, 7, w); 6];
        let g = classify(&s, &refs);
        // It must not be confidently called validity_window purely because 7/68 matches.
        assert!(
            g.as_ref().map_or(true, |g| g.name != "validity_window"),
            "shape-collision must not yield validity_window: {g:?}"
        );
    }

    #[test]
    fn genuinely_ambiguous_low_evidence_is_unknown() {
        // A single sample of a novel 6-account, 20-word program matching nothing well.
        let mut w = vec![7u32, 9, 11];
        w.resize(20, 3);
        let s = vec![Sample::new(Kind::Public, 6, w)];
        assert!(classify(&s, &refs()).is_none(), "novel program should be unknown");
    }

    #[test]
    fn register_all_zero_resolves_authenticated_transfer() {
        // authenticated_transfer init: 1 account, all-zero 4-word instruction (amount 0).
        let s = vec![Sample::new(Kind::Public, 1, vec![0, 0, 0, 0]); 3];
        let g = classify(&s, &refs()).expect("should classify");
        assert_eq!(g.name, "authenticated_transfer");
    }

    #[test]
    fn pinata_wide_solution_beats_transfer() {
        // A wide 128-bit PoW solution: all four words big => pinata, not authenticated_transfer.
        let sol: u128 = 0x1234_5678_9abc_def0_1122_3344_5566_7788;
        let s = vec![Sample::new(Kind::Public, 2, u128w(sol)); 4];
        let g = classify(&s, &refs()).expect("should classify");
        assert_eq!(g.name, "pinata");
    }

    #[test]
    fn empty_and_no_refs_are_none() {
        assert!(classify(&[], &refs()).is_none());
        let s = vec![Sample::new(Kind::Public, 2, u128w(1))];
        assert!(classify(&s, &[]).is_none());
    }
}
