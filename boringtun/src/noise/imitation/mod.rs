// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Protocol-shaped pre-handshake imitation sequences (DNS / SIP / STUN), ported
//! from wiresock's `netlib/src/wireguard/pre_handshake.h`.
//!
//! Each generator produces the standalone datagram(s) a real client emits for
//! that protocol — a STUN ICE connectivity check, a SIP INVITE/CANCEL pair, a
//! short burst of DNS queries — to camouflage the AmneziaWG handshake. They are
//! client-side cover traffic only; no server responses are synthesized.
//!
//! These need no extra dependencies (HMAC-SHA1 comes from `ring`), so unlike the
//! QUIC imitation they are always compiled. The QUIC imitation lives in
//! [`super::quic`].

pub(crate) mod detect;
pub(crate) mod dns;
pub(crate) mod sip;
pub(crate) mod stun;

use rand_core::RngCore;

/// Unreserved token alphabet (RFC 8445 ICE ufrag/pwd charset).
const TOKEN_ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A random token of `min_len..=max_len` characters from [`TOKEN_ALPHABET`].
fn random_token(min_len: usize, max_len: usize, rng: &mut impl RngCore) -> String {
    let span = (max_len - min_len + 1) as u32;
    let len = min_len + (rng.next_u32() % span) as usize;
    (0..len)
        .map(|_| TOKEN_ALPHABET[(rng.next_u32() % 62) as usize] as char)
        .collect()
}
