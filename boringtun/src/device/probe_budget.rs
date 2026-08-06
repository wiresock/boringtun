// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! An aggregate ceiling on bytes emitted in reply to *unauthenticated* traffic.
//!
//! Today the server emits nothing to an unverified source: `verify_packet`
//! computes mac1 from the server's static public key before anything is written,
//! so an attacker without that key cannot make the process produce a single
//! byte. A probe responder gives that up deliberately, and this bounds what it
//! costs.
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
        self.try_consume_at(bytes, self.now_millis())
    }

    /// Same, with an injectable clock so tests need no real sleeps.
    pub(crate) fn try_consume_at(&self, bytes: usize, now: u32) -> bool {
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

            // `now < old_ts` means the millisecond counter wrapped (~49 days) or
            // the clock moved oddly. Treat it as a full refill and re-anchor:
            // self-healing, and at worst it grants one extra second's worth.
            let elapsed = if now >= old_ts {
                now - old_ts
            } else {
                u32::MAX
            };
            let refill = (elapsed as u64).saturating_mul(self.bytes_per_sec as u64);
            let available = ((old_tokens as u64).saturating_add(refill)).min(cap);

            if available < want {
                // Store the refilled state even on refusal, so the next caller
                // does not recompute the same elapsed window.
                let new = pack(available as u32, now);
                let _ = self
                    .state
                    .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire);
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

    #[test]
    fn survives_the_millisecond_counter_wrapping() {
        let b = ProbeBudget::new(1000);
        assert!(b.try_consume_at(1000, u32::MAX - 10));
        // Wrap: `now` is now less than the stored timestamp. Must recover
        // rather than stall forever with zero elapsed time.
        assert!(
            b.try_consume_at(1000, 5),
            "wrap must not deadlock the budget"
        );
    }
}
