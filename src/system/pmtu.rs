//! Active path-MTU discovery via DF-bit ICMP echo, bisected over packet size.
//!
//! `ext_if` in the pf rules is always a VPN tunnel, and a tunnel's interface
//! MTU is an unreliable proxy for what the path can actually carry: OpenVPN-UDP
//! reports `mtu 1500` but encapsulation overhead drops the true path to ~1440,
//! so a clamp of `1500 - 40` silently black-holes full-size DF packets. This
//! module measures the real path MTU by sending DF pings of decreasing size
//! through the tunnel and bisecting for the largest that survives.
//!
//! On any inconclusive outcome (ICMP blocked, spawn error, time budget spent)
//! [`probe_path_mtu`] returns `None`; the caller then applies a conservative
//! cap rather than ever trusting the inflated interface MTU again.

use std::future::Future;
use std::time::{Duration, Instant};

use crate::system::run_cmd;

/// IPv4 + ICMP-echo header overhead. To test path MTU `M`, the ICMP payload is
/// `M - 28` (20-byte IP header + 8-byte ICMP header).
const ICMP_V4_OVERHEAD: u16 = 28;

/// Bisection granularity. Coarse enough to cap the probe count (~6 over the
/// 576..1500 range), fine enough that the resulting MSS is within 8 bytes of
/// optimal. Every size we test — and every value we return — is a multiple.
const STEP: u16 = 8;

/// Lower bound we'll probe. Real internet paths never sink below this; a path
/// that can't carry 576 means ICMP is unusable, not that the path is tiny.
const FLOOR: u16 = 576;

/// Upper bound we ever probe — nothing on these paths exceeds standard
/// Ethernet, so probing above it just wastes the budget.
const PMTU_CEILING: u16 = 1500;

/// Conservative MTU the *caller* falls back to when the probe is inconclusive.
/// Exposed so `session.rs` derives the same cap via `min(link_mtu, this)`.
pub const CONSERVATIVE_MTU: u16 = 1400;

/// Per-probe reply wait (ms). A VPN round-trip can be 100ms+; leave margin so
/// a slow-but-honest reply isn't misread as a drop.
const PROBE_WAIT_MS: u16 = 800;

/// Hard per-`ping`-process ceiling (s), so a wedged probe can't outlive its
/// slot even if `-W` is somehow ignored.
const PROBE_CEIL_S: u16 = 2;

/// Consecutive misses before we believe a size is genuinely too big. macOS
/// `ping` gives no fast "frag needed" signal and the path is non-monotonic
/// under load, so one miss can be transient loss — retry before concluding.
const FAIL_RETRIES: u8 = 2;

/// Total wall-clock budget for one discovery. Fits inside the 10s
/// start-sharing envelope alongside the ifconfig/pfctl work.
const TOTAL_BUDGET: Duration = Duration::from_secs(4);

/// Anycast hosts to probe, in order. Both are maximally ICMP-responsive and
/// egress exactly like forwarded LAN→internet traffic. The first that answers
/// the floor probe wins; if none do, ICMP is blocked on this path.
const PROBE_DESTS: &[&str] = &["1.1.1.1", "8.8.8.8"];

/// Outcome of a single size probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeOutcome {
    /// A reply came back at this size — it fits the path.
    Fits,
    /// No reply within the retry budget — too big (or the path is dead).
    TooBig,
    /// The probe couldn't run (spawn/permission error). Abort, don't retry.
    Error,
}

/// Round `x` down to the [`STEP`] grid so probes and results stay aligned.
fn snap_down(x: u16) -> u16 {
    x - (x % STEP)
}

/// Measure the path MTU of `vpn_if` by DF-ping bisection, capped by the link's
/// reported MTU. Returns the largest surviving MTU, or `None` when the probe is
/// inconclusive (ICMP blocked, errors, or budget exhausted before any size
/// passed) — the caller then applies the conservative cap. Never returns an
/// `Err`: a probe that can't run degrades to `None`, it does not abort sharing.
pub async fn probe_path_mtu(vpn_if: &str, link_mtu: u16) -> Option<u16> {
    let hi = link_mtu.min(PMTU_CEILING);
    // Try each destination in turn. `bisect_path_mtu` returns `None` only when
    // its floor gate fails (ICMP unusable for that dest) — so a `None` means
    // "try the next host" rather than "give up".
    for &dest in PROBE_DESTS {
        let start = Instant::now();
        let result = bisect_path_mtu(hi, start, |size| reliable_probe(vpn_if, dest, size)).await;
        if result.is_some() {
            return result;
        }
    }
    None
}

/// Pure, testable bisection core. `probe` answers "does a packet of this total
/// IPv4 size survive the path?"; it's injected so unit tests can feed a
/// synthetic true-path-MTU with no network.
///
/// Returns `None` iff the floor gate fails (the smallest probe didn't survive →
/// ICMP unusable). Otherwise returns the best known-good size: the converged
/// path MTU, or — if the time budget runs out mid-search — the largest size
/// confirmed so far (never below [`FLOOR`]).
async fn bisect_path_mtu<F, Fut>(hi: u16, start: Instant, probe: F) -> Option<u16>
where
    F: Fn(u16) -> Fut,
    Fut: Future<Output = ProbeOutcome>,
{
    // Floor gate: the smallest probe must survive, else ICMP is unusable here.
    if probe(FLOOR).await != ProbeOutcome::Fits {
        return None;
    }

    let hi = snap_down(hi);
    if hi <= FLOOR {
        return Some(FLOOR);
    }
    // If the interface-capped ceiling already passes, the link isn't lying —
    // no clamp reduction needed.
    if probe(hi).await == ProbeOutcome::Fits {
        return Some(hi);
    }

    // Binary search the largest surviving size on the STEP grid. `lo` is the
    // best known-good (floor passed), `hi` the smallest known-too-big.
    let mut lo = FLOOR;
    let mut hi = hi;
    while hi - lo > STEP {
        if start.elapsed() >= TOTAL_BUDGET {
            break; // out of time — return the best size confirmed so far
        }
        let mid = snap_down(lo + (hi - lo) / 2).clamp(lo + STEP, hi - STEP);
        match probe(mid).await {
            ProbeOutcome::Fits => lo = mid,
            ProbeOutcome::TooBig => hi = mid,
            ProbeOutcome::Error => break, // unusable mid-search — take best-good
        }
    }
    Some(lo)
}

/// One size determination with retry-on-failure: a `Fits` is trustworthy and
/// returns immediately, but a `TooBig` is only believed after [`FAIL_RETRIES`]
/// consecutive misses (the path is lossy/non-monotonic under load). An `Error`
/// aborts the retry loop — a probe that can't spawn won't spawn on retry.
async fn with_retries<F, Fut>(once: F) -> ProbeOutcome
where
    F: Fn() -> Fut,
    Fut: Future<Output = ProbeOutcome>,
{
    for _ in 0..=FAIL_RETRIES {
        match once().await {
            ProbeOutcome::Fits => return ProbeOutcome::Fits,
            ProbeOutcome::Error => return ProbeOutcome::Error,
            ProbeOutcome::TooBig => {}
        }
    }
    ProbeOutcome::TooBig
}

/// Network predicate for the bisection: does a DF packet of total size `size`
/// reach `dest` through `vpn_if`? Wraps [`ping_once`] in the retry policy.
fn reliable_probe<'a>(
    vpn_if: &'a str,
    dest: &'static str,
    size: u16,
) -> impl Future<Output = ProbeOutcome> + 'a {
    with_retries(move || ping_once(vpn_if, dest, size))
}

/// Send one DF-bit ICMP echo of total IPv4 size `size` to `dest`, bound to
/// `vpn_if`. Classifies on exit status only — macOS prints no remote
/// "frag needed" string, so a too-big packet is indistinguishable from a
/// black-hole at this layer: `0` = reply = [`Fits`](ProbeOutcome::Fits),
/// `2` = no reply = [`TooBig`](ProbeOutcome::TooBig), anything else (or a spawn
/// failure) = [`Error`](ProbeOutcome::Error).
async fn ping_once(vpn_if: &str, dest: &str, size: u16) -> ProbeOutcome {
    let payload = size.saturating_sub(ICMP_V4_OVERHEAD).to_string();
    let wait = PROBE_WAIT_MS.to_string();
    let ceil = PROBE_CEIL_S.to_string();
    let args = [
        "-c", "1",  // one packet
        "-D", // set the Don't-Fragment bit
        "-n", "-q", // numeric, quiet — we only read the exit status
        "-b", vpn_if, // bind egress to the tunnel
        "-s", &payload, // ICMP payload = size - 28
        "-W", &wait, // per-reply wait (ms)
        "-t", &ceil, // hard process ceiling (s)
        dest,
    ];
    match run_cmd("ping", &args).await {
        Ok(output) => match output.status.code() {
            Some(0) => ProbeOutcome::Fits,
            Some(2) => ProbeOutcome::TooBig,
            _ => ProbeOutcome::Error,
        },
        Err(_) => ProbeOutcome::Error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU8, Ordering};

    /// A synthetic path with a hard MTU at `true_mtu`: anything ≤ it fits.
    fn synthetic(true_mtu: u16) -> impl Fn(u16) -> std::future::Ready<ProbeOutcome> {
        move |size| {
            std::future::ready(if size <= true_mtu {
                ProbeOutcome::Fits
            } else {
                ProbeOutcome::TooBig
            })
        }
    }

    #[tokio::test]
    async fn converges_to_largest_grid_value_at_or_below_true_mtu() {
        // 1440 is on the STEP grid → exact.
        let r = bisect_path_mtu(1500, Instant::now(), synthetic(1440)).await;
        assert_eq!(r, Some(1440));

        // 1443 is off-grid → largest multiple of STEP at or below it.
        let r = bisect_path_mtu(1500, Instant::now(), synthetic(1443)).await;
        assert_eq!(r, Some(1440));
    }

    #[tokio::test]
    async fn honest_ceiling_returns_without_reducing() {
        // The link can carry its full (snapped) MTU — no clamp reduction.
        let r = bisect_path_mtu(1500, Instant::now(), synthetic(1500)).await;
        assert_eq!(r, Some(snap_down(1500)));
    }

    #[tokio::test]
    async fn floor_blocked_returns_none() {
        // Nothing survives, not even the floor → ICMP unusable.
        let r = bisect_path_mtu(1500, Instant::now(), |_| {
            std::future::ready(ProbeOutcome::TooBig)
        })
        .await;
        assert_eq!(r, None);
    }

    #[tokio::test]
    async fn probe_error_at_floor_returns_none() {
        let r = bisect_path_mtu(1500, Instant::now(), |_| {
            std::future::ready(ProbeOutcome::Error)
        })
        .await;
        assert_eq!(r, None);
    }

    #[tokio::test]
    async fn link_mtu_caps_the_search() {
        // Path could carry more, but the link tops out at 1280.
        let r = bisect_path_mtu(1280, Instant::now(), synthetic(2000)).await;
        assert_eq!(r, Some(snap_down(1280)));
    }

    #[tokio::test]
    async fn budget_exceeded_mid_search_returns_best_known_good() {
        // Floor passes and the ceiling fails, but the clock is already spent —
        // we must return the best confirmed size (the floor), never None.
        let past = Instant::now() - TOTAL_BUDGET - Duration::from_secs(1);
        let r = bisect_path_mtu(1500, past, synthetic(1440)).await;
        assert_eq!(r, Some(FLOOR));
    }

    #[tokio::test]
    async fn with_retries_trusts_a_late_success() {
        // First attempt is transient loss, second is a real reply.
        let calls = AtomicU8::new(0);
        let outcome = with_retries(|| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(if n == 0 {
                ProbeOutcome::TooBig
            } else {
                ProbeOutcome::Fits
            })
        })
        .await;
        assert_eq!(outcome, ProbeOutcome::Fits);
    }

    #[tokio::test]
    async fn with_retries_concludes_too_big_only_after_all_misses() {
        let calls = AtomicU8::new(0);
        let outcome = with_retries(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(ProbeOutcome::TooBig)
        })
        .await;
        assert_eq!(outcome, ProbeOutcome::TooBig);
        // 1 initial attempt + FAIL_RETRIES.
        assert_eq!(calls.load(Ordering::SeqCst), 1 + FAIL_RETRIES);
    }

    #[tokio::test]
    async fn with_retries_aborts_on_error() {
        let calls = AtomicU8::new(0);
        let outcome = with_retries(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(ProbeOutcome::Error)
        })
        .await;
        assert_eq!(outcome, ProbeOutcome::Error);
        assert_eq!(calls.load(Ordering::SeqCst), 1); // no retry on error
    }
}
