// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! QUIC Initial imitation: generate browser-fingerprinted QUIC Initial packets
//! carrying a TLS 1.3 ClientHello, for AmneziaWG pre-handshake protocol
//! camouflage.
//!
//! # Scope
//!
//! Client-side DPI camouflage only — boringtun never decrypts the emitted
//! packets, so only the *client* Initial key schedule (RFC 9001) is
//! implemented. The aim is **fingerprint parity**: the bytes a DPI classifier
//! keys on (cipher suites, supported groups, key shares, signature algorithms,
//! ALPN, the extension set, QUIC transport parameters) match the target browser
//! exactly, while inherently per-connection fields (client random, key-share
//! keys, GREASE, connection ids, extension/parameter order) vary every time,
//! exactly as real browsers do.
//!
//! Two distinct QUIC shapes exist, mirroring AmneziaWG:
//! - **S1–S4 junk prefixes** use lightweight shaped QUIC headers (handled in
//!   `amnezia.rs`); they are byte prefixes on real WireGuard packets, not full
//!   QUIC packets.
//! - **Pre-handshake junk** (this module) emits *complete* browser QUIC Initial
//!   datagram(s): the standalone packets a browser sends when opening a QUIC
//!   connection.
//!
//! # Layout
//!
//! - [`crypto`] — RFC 9001 Initial key derivation, AES-128-GCM, header
//!   protection. Pinned by RFC 9001 Appendix A.1 / FIPS-197 known-answer tests.
//! - [`varint`] — QUIC variable-length integers.
//! - [`initial`] — assemble one protected Initial (long header, CRYPTO frame at
//!   an offset, PADDING to an exact size).
//! - [`tls`] / [`profiles`] — the ClientHello serializer and the Chrome /
//!   Firefox / curl fingerprint tables.
//! - [`version_negotiation`] — the long-header parse shared with the probe
//!   classifier, and the one server-side packet this crate emits.
//! - [`generator`] — `generate_client_initials`: the full datagram sequence for
//!   a browser + SNI (two Initials for Chrome/Firefox, one for curl).
//! - `fingerprint` (test only) — decode + parse helper used to validate parity.
//!
//! # Verification
//!
//! `src/noise/quic/testdata/{chrome_147,firefox_149}_initial.bin` are real
//! browser Initials captured from `netlib/test/quic/captures` in the wiresock
//! repository. The tests (a) decrypt them with this module's own crypto and
//! confirm the documented fingerprint, and (b) generate a ClientHello and assert
//! it reproduces that same fingerprint. To target a new browser version, capture
//! its Initials, refresh the fixtures, and update the matching profile until the
//! parity tests pass.
//!
//! # Deferred
//!
//! ECH is emitted as a realistic *outer* wire shape only (the extension is
//! present so the fingerprint matches); no real Encrypted ClientHello is
//! performed.

pub(crate) mod crypto;
pub(crate) mod generator;
pub(crate) mod initial;
pub(crate) mod profiles;
pub(crate) mod tls;
pub(crate) mod varint;
pub(crate) mod version_negotiation;

#[cfg(test)]
pub(crate) mod fingerprint;
