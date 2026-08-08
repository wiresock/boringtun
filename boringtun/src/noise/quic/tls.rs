// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! TLS 1.3 ClientHello serialization for the QUIC imitation generator.
//!
//! Ported from wiresock's `quic_sni_generator.h`. Produces a Handshake-wrapped
//! ClientHello whose fingerprint (cipher suites, groups, signature algorithms,
//! extensions, transport-parameter ids) matches the configured browser profile,
//! with per-connection fields randomized via the supplied RNG.

use super::profiles::{ext, Profile, TpEntry};
use super::varint;
use rand_core::RngCore;

fn w16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn w24(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
}

fn rand_bytes(n: usize, rng: &mut impl RngCore) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v);
    v
}

/// Fisher-Yates shuffle matching the reference generator's ordering.
fn shuffle<T>(v: &mut [T], rng: &mut impl RngCore) {
    let mut i = v.len();
    while i > 1 {
        i -= 1;
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

/// 12-byte `version_information` transport parameter value (chosen v1 + random
/// `0x?a?a?a?a` version-GREASE + available_versions=[v1]).
fn version_information(rng: &mut impl RngCore) -> Vec<u8> {
    let r = rng.next_u64();
    let g = |shift: u32| -> u8 { (((r >> shift) as u8) & 0xf0) | 0x0a };
    vec![
        0,
        0,
        0,
        1, // chosen version (QUIC v1)
        g(0),
        g(8),
        g(16),
        g(24), // random GREASE version
        0,
        0,
        0,
        1, // available_versions = [v1]
    ]
}

/// Random RFC 9000 §18.1 GREASE transport-parameter id (`31k + 27`), forced to
/// an 8-byte varint encoding.
fn grease_tp_id(rng: &mut impl RngCore) -> u64 {
    let mut id = (rng.next_u64() & 0x03ff_ffff_ffff_ffff) | (1u64 << 61);
    let rem = id % 31;
    if rem != 27 {
        id += (27 + 31 - rem) % 31;
    }
    if id >= (1u64 << 62) {
        id -= 31;
    }
    id
}

fn ext_server_name(out: &mut Vec<u8>, sni: &str) {
    let mut list = Vec::new();
    list.push(0x00); // host_name
    w16(&mut list, sni.len() as u16);
    list.extend_from_slice(sni.as_bytes());

    let mut sni_all = Vec::new();
    w16(&mut sni_all, list.len() as u16);
    sni_all.extend_from_slice(&list);

    w16(out, ext::SERVER_NAME);
    w16(out, sni_all.len() as u16);
    out.extend_from_slice(&sni_all);
}

fn ext_alpn(out: &mut Vec<u8>, protos: &[&str]) {
    let mut list = Vec::new();
    for s in protos {
        if s.len() > 255 {
            continue;
        }
        list.push(s.len() as u8);
        list.extend_from_slice(s.as_bytes());
    }
    w16(out, ext::ALPN);
    w16(out, (2 + list.len()) as u16);
    w16(out, list.len() as u16);
    out.extend_from_slice(&list);
}

fn ext_u16_list(out: &mut Vec<u8>, ext_type: u16, values: &[u16]) {
    let mut list = Vec::new();
    for &v in values {
        w16(&mut list, v);
    }
    w16(out, ext_type);
    w16(out, (2 + list.len()) as u16);
    w16(out, list.len() as u16);
    out.extend_from_slice(&list);
}

fn ext_supported_versions(out: &mut Vec<u8>, vers: &[u16]) {
    let mut list = Vec::new();
    for &v in vers {
        w16(&mut list, v);
    }
    w16(out, ext::SUPPORTED_VERSIONS);
    w16(out, (1 + list.len()) as u16);
    out.push(list.len() as u8);
    out.extend_from_slice(&list);
}

fn ext_psk_ke_modes(out: &mut Vec<u8>) {
    w16(out, ext::PSK_KEY_EXCHANGE_MODES);
    w16(out, 0x0002);
    out.push(0x01); // vector length
    out.push(0x01); // psk_dhe_ke
}

fn ext_delegated_credentials(out: &mut Vec<u8>) {
    let sig_algs: [u16; 4] = [0x0403, 0x0503, 0x0603, 0x0203];
    let mut list = Vec::new();
    for &s in &sig_algs {
        w16(&mut list, s);
    }
    w16(out, ext::DELEGATED_CREDENTIALS);
    w16(out, (2 + list.len()) as u16);
    w16(out, list.len() as u16);
    out.extend_from_slice(&list);
}

fn key_share_size(group: u16) -> usize {
    match group {
        0x001d => 32,                             // X25519
        0x0017 => 65,                             // secp256r1 (0x04 || X || Y)
        super::profiles::PQ_HYBRID_GROUP => 1216, // X25519MLKEM768
        _ => 32,
    }
}

fn ext_key_share(out: &mut Vec<u8>, groups: &[u16], rng: &mut impl RngCore) {
    let mut entries = Vec::new();
    for &g in groups {
        w16(&mut entries, g);
        let size = key_share_size(g);
        w16(&mut entries, size as u16);
        if g == 0x0017 {
            entries.push(0x04); // uncompressed point prefix
            entries.extend_from_slice(&rand_bytes(size - 1, rng));
        } else {
            entries.extend_from_slice(&rand_bytes(size, rng));
        }
    }
    w16(out, ext::KEY_SHARE);
    w16(out, (2 + entries.len()) as u16);
    w16(out, entries.len() as u16);
    out.extend_from_slice(&entries);
}

fn ext_application_settings(out: &mut Vec<u8>) {
    w16(out, ext::APPLICATION_SETTINGS);
    w16(out, 5);
    out.extend_from_slice(&[0x00, 0x03, 0x02, 0x68, 0x33]); // ALPS payload for "h3"
}

/// ECH *outer* of realistic wire shape with random values. This is a shape
/// generator only — no real Encrypted ClientHello is performed (ECH crypto is
/// deferred), but the extension is present so the fingerprint matches.
fn ext_encrypted_client_hello(out: &mut Vec<u8>, rng: &mut impl RngCore) {
    w16(out, ext::ENCRYPTED_CLIENT_HELLO);
    let mut ech = Vec::new();
    ech.push(0x00); // ECHClientHello type: outer
    ech.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // HKDF-SHA256 / AES-128-GCM
    ech.push((rng.next_u64() & 0xff) as u8); // config_id
    w16(&mut ech, 32); // enc (X25519) length
    ech.extend_from_slice(&rand_bytes(32, rng));
    let payload_len = 150 + (rng.next_u64() % 51) as u16;
    w16(&mut ech, payload_len);
    ech.extend_from_slice(&rand_bytes(payload_len as usize, rng));

    w16(out, ech.len() as u16);
    out.extend_from_slice(&ech);
}

fn ext_record_size_limit(out: &mut Vec<u8>) {
    w16(out, ext::RECORD_SIZE_LIMIT);
    w16(out, 2);
    w16(out, 16385);
}

fn ext_reneg_info(out: &mut Vec<u8>) {
    w16(out, ext::RENEGOTIATION_INFO);
    w16(out, 1);
    out.push(0x00);
}

fn ext_status_request(out: &mut Vec<u8>) {
    w16(out, ext::STATUS_REQUEST);
    w16(out, 5);
    out.push(0x01); // ocsp
    w16(out, 0x0000); // responder_id_list length
    w16(out, 0x0000); // request_extensions length
}

fn ext_extended_master_secret(out: &mut Vec<u8>) {
    w16(out, ext::EXTENDED_MASTER_SECRET);
    w16(out, 0);
}

fn ext_compress_cert(out: &mut Vec<u8>, firefox_mode: bool) {
    w16(out, ext::COMPRESS_CERTIFICATE);
    if firefox_mode {
        w16(out, 7);
        out.push(6); // algorithms vector length
        w16(out, 1); // zlib
        w16(out, 3); // zstd
        w16(out, 2); // brotli
    } else {
        w16(out, 3);
        out.push(2);
        w16(out, 2); // brotli
    }
}

fn ext_quic_tp(out: &mut Vec<u8>, profile: &Profile, scid: &[u8], rng: &mut impl RngCore) {
    // Materialize each parameter to (id, value bytes).
    let mut params: Vec<(u64, Vec<u8>)> = Vec::with_capacity(profile.quic_tp.len());
    for entry in &profile.quic_tp {
        let resolved = match entry {
            TpEntry::Varint(id, v) => {
                let mut vi = Vec::new();
                varint::write(&mut vi, *v);
                (*id, vi)
            }
            TpEntry::Bytes(id, b) => (*id, b.clone()),
            TpEntry::VersionInfo(id) => (*id, version_information(rng)),
            TpEntry::ScidSource(id) => (*id, scid.to_vec()),
            TpEntry::Grease => (grease_tp_id(rng), rand_bytes(6, rng)),
        };
        params.push(resolved);
    }
    shuffle(&mut params, rng);

    let mut body = Vec::new();
    for (id, value) in &params {
        varint::write(&mut body, *id);
        varint::write(&mut body, value.len() as u64);
        body.extend_from_slice(value);
    }

    w16(out, ext::QUIC_TRANSPORT_PARAMS);
    w16(out, body.len() as u16);
    out.extend_from_slice(&body);
}

fn build_extension(
    out: &mut Vec<u8>,
    t: u16,
    profile: &Profile,
    sni: &str,
    scid: &[u8],
    rng: &mut impl RngCore,
) {
    match t {
        ext::SERVER_NAME => ext_server_name(out, sni),
        ext::ALPN => ext_alpn(out, &profile.alpn),
        ext::SUPPORTED_GROUPS => {
            ext_u16_list(out, ext::SUPPORTED_GROUPS, &profile.supported_groups)
        }
        ext::SIGNATURE_ALGORITHMS => ext_u16_list(
            out,
            ext::SIGNATURE_ALGORITHMS,
            &profile.signature_algorithms,
        ),
        ext::SUPPORTED_VERSIONS => ext_supported_versions(out, &profile.supported_versions),
        ext::PSK_KEY_EXCHANGE_MODES => ext_psk_ke_modes(out),
        ext::KEY_SHARE => ext_key_share(out, &profile.key_share_groups, rng),
        ext::QUIC_TRANSPORT_PARAMS => ext_quic_tp(out, profile, scid, rng),
        ext::COMPRESS_CERTIFICATE => ext_compress_cert(
            out,
            profile.name == super::profiles::BrowserProfile::Firefox,
        ),
        ext::RECORD_SIZE_LIMIT => ext_record_size_limit(out),
        ext::RENEGOTIATION_INFO => ext_reneg_info(out),
        ext::STATUS_REQUEST => ext_status_request(out),
        ext::EXTENDED_MASTER_SECRET => ext_extended_master_secret(out),
        ext::DELEGATED_CREDENTIALS => ext_delegated_credentials(out),
        ext::APPLICATION_SETTINGS => {
            if profile.include_unknown_17613 {
                ext_application_settings(out);
            }
        }
        ext::ENCRYPTED_CLIENT_HELLO if profile.enable_ech => ext_encrypted_client_hello(out, rng),
        _ => {}
    }
}

/// Generate a complete TLS Handshake ClientHello message for `profile`,
/// carrying `sni`. `scid` is the QUIC long-header Source Connection ID (used by
/// profiles that mirror it in transport parameter 0x0f).
pub(crate) fn generate_client_hello(
    profile: &Profile,
    sni: &str,
    scid: &[u8],
    rng: &mut impl RngCore,
) -> Vec<u8> {
    let mut ch = Vec::with_capacity(2048);

    w16(&mut ch, 0x0303); // legacy_version (TLS 1.2)
    ch.extend_from_slice(&rand_bytes(32, rng)); // client_random

    if profile.use_empty_session_id {
        ch.push(0x00);
    } else {
        ch.push(0x20);
        ch.extend_from_slice(&rand_bytes(32, rng));
    }

    w16(&mut ch, (profile.cipher_suites.len() * 2) as u16);
    for &cs in &profile.cipher_suites {
        w16(&mut ch, cs);
    }

    ch.push(0x01); // compression methods length
    ch.push(0x00); // null compression

    let ext_len_pos = ch.len();
    w16(&mut ch, 0); // extensions length placeholder
    let ext_start = ch.len();

    let mut order = profile.extensions_order.clone();
    if profile.randomize_extensions_order {
        shuffle(&mut order, rng);
    }
    for t in order {
        build_extension(&mut ch, t, profile, sni, scid, rng);
    }

    let ext_total = (ch.len() - ext_start) as u16;
    ch[ext_len_pos..ext_len_pos + 2].copy_from_slice(&ext_total.to_be_bytes());

    let mut hs = Vec::with_capacity(ch.len() + 4);
    hs.push(0x01); // ClientHello
    w24(&mut hs, ch.len() as u32);
    hs.extend_from_slice(&ch);
    hs
}
