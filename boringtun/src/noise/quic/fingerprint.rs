// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Test-only QUIC Initial decoder and TLS ClientHello fingerprint parser.
//!
//! Used to (a) cross-validate the Initial crypto against real browser captures
//! and (b) extract the reference fingerprint that the generated profiles must
//! reproduce. Kept deliberately small: it parses only the fields the browser
//! profiles are calibrated against.

#![cfg(test)]

use super::crypto;
use super::varint;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};

/// The TLS ClientHello fields a browser fingerprint is keyed on.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Fingerprint {
    pub legacy_session_id_len: usize,
    pub cipher_suites: Vec<u16>,
    /// Extension types in wire order (order is randomized per connection).
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub alpn: Vec<String>,
    pub sni: Option<String>,
    /// QUIC transport-parameter ids (order is randomized per connection).
    pub transport_param_ids: Vec<u64>,
}

impl Fingerprint {
    /// Extension types as a sorted set (order-independent comparison).
    pub(crate) fn extension_set(&self) -> Vec<u16> {
        let mut v = self.extensions.clone();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Transport-parameter ids as a sorted set.
    pub(crate) fn transport_param_set(&self) -> Vec<u64> {
        let mut v = self.transport_param_ids.clone();
        v.sort_unstable();
        v.dedup();
        v
    }
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Decrypt a client Initial packet and return the plaintext QUIC frames.
pub(crate) fn open_initial(packet: &[u8]) -> Vec<u8> {
    let mut pos = 1 + 4; // first byte + version
    let dcid_len = packet[pos] as usize;
    pos += 1;
    let dcid = &packet[pos..pos + dcid_len];
    pos += dcid_len;
    let scid_len = packet[pos] as usize;
    pos += 1 + scid_len;
    let token_len = packet[pos] as usize; // browsers use 0
    pos += 1 + token_len;
    let (length, len_sz) = varint::read(&packet[pos..]).unwrap();
    pos += len_sz;
    let pn_offset = pos;

    let keys = crypto::derive_initial_keys(&crypto::INITIAL_SALT_V1, dcid);

    let mut buf = packet.to_vec();
    let sample_offset = pn_offset + 4;
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&buf[sample_offset..sample_offset + 16]);
    let mask = crypto::aes_ecb_block(&keys.hp, &sample);
    buf[0] ^= mask[0] & 0x0f;
    let pn_len = ((buf[0] & 0x03) + 1) as usize;
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[1 + i];
    }

    let pn_bytes = buf[pn_offset..pn_offset + pn_len].to_vec();
    let aad = buf[..pn_offset + pn_len].to_vec();
    let ciphertext = &buf[pn_offset + pn_len..pn_offset + length as usize];

    let mut nonce = keys.iv;
    let off = nonce.len() - pn_bytes.len();
    for (i, b) in pn_bytes.iter().enumerate() {
        nonce[off + i] ^= b;
    }
    let unbound = UnboundKey::new(&AES_128_GCM, &keys.key).unwrap();
    let opening = LessSafeKey::new(unbound);
    let mut ct = ciphertext.to_vec();
    let plaintext = opening
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&aad),
            &mut ct,
        )
        .expect("real capture must authenticate under derived Initial keys");
    plaintext.to_vec()
}

/// Reassemble the CRYPTO stream (offset-ordered) from QUIC frames, skipping
/// PADDING/PING and any other frames present.
pub(crate) fn reassemble_crypto(frames: &[u8]) -> Vec<u8> {
    let mut fragments: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut p = frames;
    while !p.is_empty() {
        let ty = p[0];
        p = &p[1..];
        match ty {
            0x00 | 0x01 => {} // PADDING / PING: no body
            0x06 => {
                let (offset, a) = varint::read(p).unwrap();
                p = &p[a..];
                let (len, b) = varint::read(p).unwrap();
                p = &p[b..];
                let len = len as usize;
                fragments.push((offset, p[..len].to_vec()));
                p = &p[len..];
            }
            other => panic!("unexpected QUIC frame type {:#x} in Initial", other),
        }
    }
    fragments.sort_by_key(|(off, _)| *off);
    fragments.into_iter().flat_map(|(_, d)| d).collect()
}

/// Parse the subset of ClientHello fields used for fingerprint comparison.
pub(crate) fn parse_clienthello(ch: &[u8]) -> Fingerprint {
    let mut fp = Fingerprint::default();
    assert_eq!(ch[0], 0x01, "handshake type must be ClientHello");
    // 1 type + 3 length + 2 legacy_version + 32 random
    let mut p = 1 + 3 + 2 + 32;
    let sid_len = ch[p] as usize;
    fp.legacy_session_id_len = sid_len;
    p += 1 + sid_len;

    let cs_len = be16(&ch[p..]) as usize;
    p += 2;
    for c in ch[p..p + cs_len].chunks_exact(2) {
        fp.cipher_suites.push(be16(c));
    }
    p += cs_len;

    let comp_len = ch[p] as usize;
    p += 1 + comp_len;

    let ext_total = be16(&ch[p..]) as usize;
    p += 2;
    let ext_end = p + ext_total;
    while p + 4 <= ext_end {
        let ext_type = be16(&ch[p..]);
        let ext_len = be16(&ch[p + 2..]) as usize;
        let body = &ch[p + 4..p + 4 + ext_len];
        fp.extensions.push(ext_type);
        parse_extension(&mut fp, ext_type, body);
        p += 4 + ext_len;
    }
    fp
}

fn parse_extension(fp: &mut Fingerprint, ext_type: u16, body: &[u8]) {
    match ext_type {
        0x0000 => {
            // server_name: list(2) { type(1) len(2) name }
            if body.len() >= 5 && body[2] == 0 {
                let nlen = be16(&body[3..]) as usize;
                fp.sni = Some(String::from_utf8_lossy(&body[5..5 + nlen]).into_owned());
            }
        }
        0x000a => {
            let n = be16(&body[0..]) as usize;
            for g in body[2..2 + n].chunks_exact(2) {
                fp.supported_groups.push(be16(g));
            }
        }
        0x000d => {
            let n = be16(&body[0..]) as usize;
            for s in body[2..2 + n].chunks_exact(2) {
                fp.signature_algorithms.push(be16(s));
            }
        }
        0x0010 => {
            // ALPN: list(2) { len(1) proto }*
            let mut q = 2usize;
            while q < body.len() {
                let l = body[q] as usize;
                q += 1;
                fp.alpn
                    .push(String::from_utf8_lossy(&body[q..q + l]).into_owned());
                q += l;
            }
        }
        0x002b => {
            let n = body[0] as usize;
            for v in body[1..1 + n].chunks_exact(2) {
                fp.supported_versions.push(be16(v));
            }
        }
        0x0033 => {
            // key_share: list(2) { group(2) len(2) key }*
            let mut q = 2usize;
            while q + 4 <= body.len() {
                let group = be16(&body[q..]);
                let klen = be16(&body[q + 2..]) as usize;
                fp.key_share_groups.push(group);
                q += 4 + klen;
            }
        }
        0x0039 => {
            // QUIC transport parameters: { id(varint) len(varint) value }*
            let mut q = 0usize;
            while q < body.len() {
                let (id, a) = varint::read(&body[q..]).unwrap();
                q += a;
                let (vlen, b) = varint::read(&body[q..]).unwrap();
                q += b + vlen as usize;
                fp.transport_param_ids.push(id);
            }
        }
        _ => {}
    }
}

/// Split a fixture blob of 2-byte-big-endian length-prefixed Initial packets.
pub(crate) fn split_records(blob: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut p = 0;
    while p + 2 <= blob.len() {
        let len = be16(&blob[p..]) as usize;
        p += 2;
        out.push(&blob[p..p + len]);
        p += len;
    }
    out
}

/// Decode a capture (one or more coalesced/split Initials for a single flow)
/// end-to-end into its ClientHello fingerprint. Browsers split a modern
/// ClientHello (≈1.4 KB with an MLKEM768 key share) across two Initial packets;
/// the CRYPTO stream is reassembled by offset across all of them.
pub(crate) fn fingerprint_of_capture(blob: &[u8]) -> Fingerprint {
    let mut frames = Vec::new();
    for initial in split_records(blob) {
        frames.extend_from_slice(&open_initial(initial));
    }
    let ch = reassemble_crypto(&frames);
    parse_clienthello(&ch)
}

mod tests {
    use super::*;

    const CHROME_147: &[u8] = include_bytes!("testdata/chrome_147_initial.bin");
    const FIREFOX_149: &[u8] = include_bytes!("testdata/firefox_149_initial.bin");

    /// Decrypt the real Chrome 147 Initial with our own Initial crypto and
    /// confirm the documented fingerprint (captures/README.md).
    #[test]
    fn chrome_147_capture_matches_documented_fingerprint() {
        let fp = fingerprint_of_capture(CHROME_147);

        assert_eq!(fp.legacy_session_id_len, 0);
        assert_eq!(fp.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
        assert_eq!(fp.supported_groups, vec![0x11ec, 0x001d, 0x0017, 0x0018]);
        assert_eq!(fp.key_share_groups, vec![0x11ec, 0x001d]);
        assert_eq!(
            fp.signature_algorithms,
            vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]
        );
        assert_eq!(fp.supported_versions, vec![0x0304]);
        assert_eq!(fp.alpn, vec!["h3".to_string()]);
        assert_eq!(
            fp.extension_set(),
            vec![
                0x0000, 0x000a, 0x000d, 0x0010, 0x001b, 0x002b, 0x002d, 0x0033, 0x0039, 0x44cd,
                0xfe0d
            ]
        );
        assert!(fp.sni.is_some(), "Chrome ClientHello carries an SNI");
    }

    /// Decrypt the real Firefox 149 Initial and confirm its documented
    /// fingerprint.
    #[test]
    fn firefox_149_capture_matches_documented_fingerprint() {
        let fp = fingerprint_of_capture(FIREFOX_149);

        assert_eq!(fp.legacy_session_id_len, 0);
        assert_eq!(fp.cipher_suites, vec![0x1301, 0x1303, 0x1302]);
        assert_eq!(
            fp.supported_groups,
            vec![0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]
        );
        assert_eq!(fp.key_share_groups, vec![0x11ec, 0x001d, 0x0017]);
        assert_eq!(
            fp.signature_algorithms,
            vec![
                0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
                0x0201
            ]
        );
        assert_eq!(fp.supported_versions, vec![0x0304]);
        assert_eq!(fp.alpn, vec!["h3".to_string()]);
        assert_eq!(
            fp.extension_set(),
            vec![
                0x0000, 0x0005, 0x000a, 0x000d, 0x0010, 0x0017, 0x001b, 0x001c, 0x0022, 0x002b,
                0x002d, 0x0033, 0x0039, 0xfe0d, 0xff01
            ]
        );
        assert!(fp.sni.is_some(), "Firefox ClientHello carries an SNI");
    }
}
