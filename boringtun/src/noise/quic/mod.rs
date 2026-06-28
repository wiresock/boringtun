// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! QUIC Initial imitation: generate browser-fingerprinted QUIC Initial packets
//! carrying a TLS 1.3 ClientHello, for AmneziaWG pre-handshake protocol
//! camouflage.
//!
//! This is client-side DPI camouflage only — boringtun never decrypts the
//! emitted packets, so only the *client* Initial key schedule (RFC 9001) is
//! implemented. The S1–S4 junk prefixes use lightweight shaped headers
//! elsewhere; this module is exercised exclusively by the standalone
//! pre-handshake junk path.
//
// The generator is built bottom-up (Phase A: crypto + framing, Phase B:
// ClientHello profiles); it is consumed by the pre-handshake QUIC path once the
// `amnezia` integration lands (Phase C). Until then the lower layers are only
// reachable from their own tests, so silence dead-code warnings module-wide.
#![allow(dead_code)]

pub(crate) mod crypto;
pub(crate) mod initial;
pub(crate) mod varint;
