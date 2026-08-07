// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! An aggregate ceiling on bytes emitted in reply to *unauthenticated* traffic.
//!
//! An earlier version of this paragraph claimed the server emitted *nothing* to
//! an unverified source, on the grounds that `verify_packet` checks mac1 before
//! anything is written. That was wrong twice over, and the error is worth
//! keeping visible because it is the blind spot that left the cookie path
//! unguarded for as long as it was. mac1 is keyed on the server's *public* key,
//! which is in every client configuration, so it authenticates nobody; and a
//! cookie reply is a write to an unverified source by design — it is how
//! WireGuard proves an address is real.
//!
//! What was true is that the cookie path is bounded in a way the probe
//! responder is not: it fires only while the limiter is under load, and
//! [`super::reply_policy`] now holds it to the size of the datagram that
//! provoked it. A probe responder answers anything, at any rate, so it needs a
//! ceiling of its own — and this is it.
//!
//! Three properties, each chosen against a specific failure:
//!
//! - **Keyed by nothing.** A per-source limiter is defeated by spoofing: every
//!   forged address gets a fresh allowance. There is no input an attacker
//!   controls that grants more budget here.
//! - **Counts bytes, not packets.** Amplification is a byte ratio. A reply that
//!   is larger than its request is the thing worth bounding.
//! - **Refills smoothly rather than resetting on a tick.** A per-second reset
//!   makes replies arrive in a square wave whose phase is the process's own
//!   timer phase — stable for the process lifetime and observable across
//!   source addresses, which is a fingerprint rather than a defence. Tokens
//!   here accrue continuously, capped at one second's worth so an idle port
//!   still cannot bank a burst.
//!
//! Draining the budget silences probe replies, degrading camouflage to the
//! silence a bare WireGuard port already gives. It never affects the tunnel:
//! authenticated traffic does not draw on it.

// Edition 2018: `TryFrom` is not in the prelude (it arrived in 2021).
use std::convert::TryFrom;

// `portable_atomic`, not `std`, and specifically for the 64-bit width:
// `AtomicU64` does not exist on targets without native 64-bit atomics, which
// includes 32-bit ARM. The crate already depends on portable-atomic with the
// `fallback` feature for exactly this, and every other `AtomicU64` here --
// `noise::session` and `noise::rate_limiter` -- takes it from there. The
// `AtomicBool`/`AtomicUsize` in `device::mod` stay on `std` because those
// widths are available everywhere.
use portable_atomic::{AtomicU64, Ordering};

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

/// Fixed-point scale for the token count, so sub-byte refill increments are not
/// rounded away.
const MILLI: u64 = 1000;

/// The largest rate the packed 32-bit token field can represent.
///
/// Above this, a full second of refill exceeds `u32::MAX` millibytes and the
/// balance truncates on store -- 10 MB/s would silently behave as roughly
/// 1.4 MB/s, which is worse than refusing the value because the operator gets
/// a number they never chose. [`ProbeBudget::new`] clamps to it.
///
/// ~4.29 MB/s, which is three orders of magnitude above anything camouflage
/// needs; the clamp exists for correctness, not as a policy.
const MAX_BYTES_PER_SEC: u32 = (u32::MAX as u64 / MILLI) as u32;

pub(crate) struct ProbeBudget {
    /// Packed: high 32 bits = millibytes available, low 32 = milliseconds since
    /// `start`. One atomic so a refill and a spend are a single CAS, with no
    /// lock on the ingress path.
    state: AtomicU64,
    start: Instant,
    /// Allowance per second, in bytes. Also the cap: unused allowance stops
    /// accruing here, which is what prevents an idle port banking a burst.
    bytes_per_sec: u32,
}

fn pack(millibytes: u32, millis: u32) -> u64 {
    ((millibytes as u64) << 32) | (millis as u64)
}

fn unpack(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v as u32)
}

impl ProbeBudget {
    pub(crate) fn new(bytes_per_sec: u32) -> Self {
        // Clamp here rather than at the use sites: with this held, `cap` fits
        // u32 by construction and every later `as u32` is lossless.
        if bytes_per_sec > MAX_BYTES_PER_SEC {
            // The module doc argues the clamp beats truncation because the
            // operator would otherwise "get a number they never chose". They
            // still get one -- just a different one -- so say so.
            tracing::warn!(
                message = "probe reply rate clamped",
                requested = bytes_per_sec,
                using = MAX_BYTES_PER_SEC
            );
        }
        let bytes_per_sec = bytes_per_sec.min(MAX_BYTES_PER_SEC);
        Self {
            state: AtomicU64::new(pack((bytes_per_sec as u64 * MILLI) as u32, 0)),
            start: Instant::now(),
            bytes_per_sec,
        }
    }

    fn now_millis(&self) -> u32 {
        self.start.elapsed().as_millis() as u32
    }

    /// Reserve `bytes` of allowance. `true` means the caller may send.
    ///
    /// Charge *before* writing to the socket, not after: charging afterwards
    /// leaves a window in which an unbounded burst is admitted between the
    /// check and the accounting.
    pub(crate) fn try_consume(&self, bytes: usize) -> bool {
        // The clock is read *inside* the retry loop, not snapshotted here.
        //
        // One budget is shared by every worker -- `Device::probe_responder`
        // holds the only one, and every thread reaches it through the device
        // read guard -- so a thread that read the clock at millisecond 99 can
        // find millisecond 100 already stored by a thread that read it later.
        // With a snapshot taken once up front, that thread sees `now < old_ts`
        // on every retry and takes the wrap branch below -- which grants a
        // *full* refill. That is not the rare 49-day event the branch was
        // written for; it is ordinary contention under exactly the flood this
        // ceiling exists to bound.
        //
        // Reading after the state load makes it impossible: whatever `old_ts`
        // we observe was stored by a thread whose own read happened before our
        // load, so a monotonic clock cannot hand us anything smaller.
        self.consume(bytes, || self.now_millis())
    }

    /// Same, with an injectable clock so tests need no real sleeps.
    ///
    /// `#[cfg(test)]`: production always uses the real clock, and the whole
    /// point of `try_consume` is *where* it reads that clock.
    #[cfg(test)]
    pub(crate) fn try_consume_at(&self, bytes: usize, now: u32) -> bool {
        self.consume(bytes, || now)
    }

    /// `clock` is called once per attempt, after the state load. See
    /// [`Self::try_consume`] for why that ordering is load-bearing.
    fn consume(&self, bytes: usize, clock: impl Fn() -> u32) -> bool {
        let cap = (self.bytes_per_sec as u64).saturating_mul(MILLI);
        // A single reply larger than the whole per-second allowance can never
        // be admitted; refuse rather than spin.
        let want = match u32::try_from(bytes) {
            Ok(b) if (b as u64).saturating_mul(MILLI) <= cap => (b as u64) * MILLI,
            _ => return false,
        };

        loop {
            let old = self.state.load(Ordering::Acquire);
            let (old_tokens, old_ts) = unpack(old);
            let now = clock();

            // `now < old_ts` means the millisecond counter wrapped (~49 days),
            // the clock moved oddly, or two workers interleaved their reads.
            // Grant *no* refill and re-anchor on `now`, rather than treating it
            // as a full second's worth.
            //
            // The earlier `u32::MAX` here was a ceiling bypass: it saturated the
            // bucket back to `cap`, so any thread whose clock read landed behind
            // another's stored timestamp handed itself a full allowance. Costing
            // one refill-less call instead is strictly safer -- the store below
            // re-anchors immediately, so the stall lasts exactly one call, and
            // an attacker gains nothing from provoking it.
            let elapsed = now.saturating_sub(old_ts);
            let refill = (elapsed as u64).saturating_mul(self.bytes_per_sec as u64);
            let available = ((old_tokens as u64).saturating_add(refill)).min(cap);

            if available < want {
                // Store the refilled state even on refusal, so the next caller
                // does not recompute the same elapsed window -- but only when
                // there is something to store. Once the bucket is empty and no
                // time has passed, `new == old`, and issuing the CAS anyway
                // would put a contended read-modify-write on this cache line
                // for every refused datagram of a flood, which is the state
                // this ceiling puts the process into by design.
                let new = pack(available as u32, now);
                if new != old {
                    let _ =
                        self.state
                            .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire);
                }
                return false;
            }

            let new = pack((available - want) as u32, now);
            if self
                .state
                .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
            // Lost the race; recompute against the winner's state.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_bytes_within_a_second() {
        let b = ProbeBudget::new(1000);
        assert!(b.try_consume_at(600, 0));
        assert!(b.try_consume_at(400, 0));
        assert!(!b.try_consume_at(1, 0), "allowance exactly exhausted");
    }

    #[test]
    fn refills_smoothly_rather_than_on_a_boundary() {
        let b = ProbeBudget::new(1000);
        assert!(b.try_consume_at(1000, 0));
        assert!(!b.try_consume_at(100, 0));
        // Half a second in, half the allowance is back -- no waiting for a tick.
        assert!(b.try_consume_at(500, 500));
        assert!(!b.try_consume_at(1, 500));
    }

    #[test]
    fn does_not_bank_idle_allowance() {
        // The earlier timestamp is load-bearing: without spending at t=0 this
        // asserts nothing that `bounds_bytes_within_a_second` does not.
        let b = ProbeBudget::new(1000);
        assert!(b.try_consume_at(1000, 0));
        // Ten idle seconds. An accruing bucket would hold 10_000 by now.
        assert!(b.try_consume_at(1000, 10_000), "one second's worth is back");
        assert!(!b.try_consume_at(1, 10_000), "and not a byte more");
    }

    #[test]
    fn is_not_keyed_on_anything_spoofable() {
        // The regression this guards: 1000 distinct "sources" share one
        // allowance. If this ever becomes per-source, the loop admits 1000.
        let b = ProbeBudget::new(1000);
        let admitted = (0..1000).filter(|_| b.try_consume_at(100, 0)).count();
        assert_eq!(admitted, 10);
    }

    #[test]
    fn refuses_a_reply_larger_than_the_whole_allowance() {
        let b = ProbeBudget::new(100);
        assert!(!b.try_consume_at(101, 0));
        // And the allowance is intact for replies that do fit.
        assert!(b.try_consume_at(100, 0));
    }

    /// A rate the packed 32-bit token field cannot represent must not silently
    /// become an unrelated smaller one.
    ///
    /// `cap` is computed in u64 but stored through a u32 cast, so an unclamped
    /// rate above ~4.29 MB/s truncates on refill: 10 MB/s would wrap to about
    /// 1.4 MB/s, and the operator gets a number they never asked for. The
    /// constructor clamps instead, so an out-of-range rate behaves exactly as
    /// the maximum representable one.
    #[test]
    fn a_rate_beyond_the_packing_limit_is_clamped_not_truncated() {
        let drain_then_measure = |rate: u32| -> u64 {
            let b = ProbeBudget::new(rate);
            while b.try_consume_at(1_000, 0) {}
            let mut got = 0u64;
            // One second later a full second's allowance must be available.
            while b.try_consume_at(1_000, 1_000) {
                got += 1_000;
            }
            got
        };

        let clamped = drain_then_measure(MAX_BYTES_PER_SEC);
        let over = drain_then_measure(10_000_000);

        assert!(
            clamped >= MAX_BYTES_PER_SEC as u64 - 1_000,
            "a second of refill at the maximum rate should yield ~{} bytes, got {}",
            MAX_BYTES_PER_SEC,
            clamped
        );
        assert_eq!(
            over, clamped,
            "an over-range rate must behave as the clamped maximum, not wrap to something smaller"
        );
    }

    /// The wrap must re-anchor rather than stall forever — but it must not pay
    /// for the recovery with a free bucket.
    ///
    /// The previous version of this test asserted the call immediately after the
    /// wrap *succeeds*, which pinned the full-refill branch as correct. That
    /// branch was reachable by ordinary worker contention, not just once every
    /// 49 days, and it was a ceiling bypass. See
    /// [`a_lagging_clock_read_cannot_refill_the_bucket`].
    #[test]
    fn the_millisecond_wrap_re_anchors_without_granting_a_free_refill() {
        let b = ProbeBudget::new(1000);
        assert!(b.try_consume_at(1000, u32::MAX - 10));

        // Wrap: `now` is below the stored timestamp. No refill is owed — no
        // time has demonstrably passed — so this is refused.
        assert!(
            !b.try_consume_at(1000, 5),
            "a wrap must not hand out a second's allowance"
        );
        // But it re-anchored on the new clock, so the next real second works.
        // Recovery costs exactly one call, not a deadlock.
        assert!(
            b.try_consume_at(1000, 1005),
            "after re-anchoring, a full second of elapsed time must refill"
        );
    }

    /// The ceiling bypass this module exists to prevent, in the form it actually
    /// occurs: several workers sharing one budget, whose clock reads interleave.
    ///
    /// Worker A reads millisecond 99 and worker B reads 100. If A's stale read
    /// is compared against B's stored timestamp, A sees `now < old_ts` and — in
    /// the original code — took the wrap branch, saturating the bucket back to
    /// `cap`. Alternating like that admitted 50x the configured rate inside a
    /// single millisecond.
    ///
    /// `try_consume_at` is the single-threaded stand-in for that interleaving:
    /// it feeds exactly the sequence of `now` values two racing workers produce,
    /// which is deterministic where spawning threads would not be.
    #[test]
    fn a_lagging_clock_read_cannot_refill_the_bucket() {
        let b = ProbeBudget::new(1000);

        // Spend the whole allowance at t=100.
        assert!(b.try_consume_at(1000, 100));
        assert!(!b.try_consume_at(1, 100), "the allowance is spent");

        // Now the lagging worker arrives with its earlier reading, 50 times.
        let mut admitted = 0;
        for _ in 0..50 {
            if b.try_consume_at(1000, 99) {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted, 0,
            "a clock read behind the stored timestamp must not refill; \
             {admitted} of 50 lagging calls were admitted"
        );
    }

    /// The same property against the real clock, through the public entry point,
    /// with every worker charging one shared budget the way `Device` does.
    ///
    /// Deliberately not a deterministic test — it is the one that would have
    /// caught the bug without anyone first suspecting it. It cannot produce a
    /// false failure: the assertion is a ceiling, and the ceiling is generous.
    #[test]
    fn concurrent_workers_cannot_exceed_the_ceiling() {
        use std::sync::atomic::{AtomicUsize, Ordering as O};
        use std::sync::Arc;

        const RATE: u32 = 1000;
        const WORKERS: usize = 4;
        const PER_WORKER: usize = 20_000;

        let budget = Arc::new(ProbeBudget::new(RATE));
        let admitted = Arc::new(AtomicUsize::new(0));

        let start = Instant::now();
        let threads: Vec<_> = (0..WORKERS)
            .map(|_| {
                let budget = Arc::clone(&budget);
                let admitted = Arc::clone(&admitted);
                std::thread::spawn(move || {
                    for _ in 0..PER_WORKER {
                        if budget.try_consume(10) {
                            admitted.fetch_add(10, O::Relaxed);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let elapsed_ms = start.elapsed().as_millis() as u64;

        // One second's worth to start, plus the refill actually earned, plus a
        // whole extra second of slack so timing jitter can never fail this.
        let ceiling = RATE as u64 * 2 + (elapsed_ms * RATE as u64) / 1000;
        let got = admitted.load(O::Relaxed) as u64;
        // Explicit arguments, not inline captures: in edition 2018 a
        // two-argument `assert!` is the legacy panic form and prints `{got}`
        // verbatim instead of interpolating. `assert_eq!` routes through
        // `format_args!` and does not have this problem, which is why only the
        // `assert!` sites need it.
        assert!(
            got <= ceiling,
            "{} workers admitted {} bytes in {} ms against a {} B/s ceiling              (bound {}); the budget is not aggregate",
            WORKERS,
            got,
            elapsed_ms,
            RATE,
            ceiling
        );
    }
}
