// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! STUN Binding Request imitation (RFC 5389 / RFC 8445 ICE), ported from
//! wiresock's `build_stun_binding_request_packet` / `simulate_stun_request`.
//!
//! Emits two client-side ICE connectivity checks: a Binding Request, then a
//! second with a fresh transaction id and USE-CANDIDATE (the nomination check).
//! Each carries SOFTWARE, USERNAME, PRIORITY, ICE-CONTROLLING, MESSAGE-INTEGRITY
//! (HMAC-SHA1) and FINGERPRINT (CRC-32). The credentials have no security
//! meaning — the packets go to the WireGuard endpoint, not a STUN server; the
//! HMAC/CRC are purely cover traffic.

use super::random_token;
use rand_core::RngCore;
use ring::hmac;

/// Plausible SOFTWARE values; deliberately generic ICE/VoIP stacks, never a
/// product-specific string that would itself be a fingerprint.
const SOFTWARE_POOL: [&str; 5] = [
    "libnice 0.1.21",
    "PJSIP 2.13.0",
    "Chromium",
    "Linphone/5.2",
    "Mozilla",
];

const HEADER_LEN: usize = 20;
const MI_ATTR_LEN: usize = 4 + 20; // type+len + HMAC-SHA1
const FP_ATTR_LEN: usize = 4 + 4; // type+len + CRC-32
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

struct BindingRequest<'a> {
    software: &'a str,
    username: &'a str,
    priority: u32,
    ice_controlling: u64,
    trans_id: [u8; 12],
    ice_pwd: &'a [u8],
    with_use_candidate: bool,
}

fn padded(len: usize) -> usize {
    (len + 3) & !3
}

fn write_tlv(pkt: &mut [u8], off: usize, attr_type: u16, attr_len: u16) {
    pkt[off..off + 2].copy_from_slice(&attr_type.to_be_bytes());
    pkt[off + 2..off + 4].copy_from_slice(&attr_len.to_be_bytes());
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let k = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let tag = hmac::sign(&k, data);
    let mut out = [0u8; 20];
    out.copy_from_slice(tag.as_ref());
    out
}

/// CRC-32 (IEEE 802.3, reflected) used by the STUN FINGERPRINT attribute.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Build one STUN Binding Request with the MI-then-FP length-patching invariant
/// (RFC 5389 §15.4 / §15.5).
fn build_binding_request(p: &BindingRequest) -> Vec<u8> {
    let software_padded = padded(p.software.len());
    let username_padded = padded(p.username.len());

    let base_attrs_len = (4 + software_padded)
        + (4 + username_padded)
        + (4 + 4) // PRIORITY
        + (4 + 8) // ICE-CONTROLLING
        + if p.with_use_candidate { 4 } else { 0 };
    let total = HEADER_LEN + base_attrs_len + MI_ATTR_LEN + FP_ATTR_LEN;

    // Zero-initialized: attribute value padding bytes must be zero for the
    // HMAC/CRC to be correct.
    let mut pkt = vec![0u8; total];

    // Header. Message Length initially covers base attrs + MI (not FP).
    let len_with_mi = (base_attrs_len + MI_ATTR_LEN) as u16;
    pkt[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
    pkt[2..4].copy_from_slice(&len_with_mi.to_be_bytes());
    pkt[4..8].copy_from_slice(&MAGIC_COOKIE);
    pkt[8..20].copy_from_slice(&p.trans_id);

    let mut off = HEADER_LEN;

    write_tlv(&mut pkt, off, 0x8022, p.software.len() as u16); // SOFTWARE
    pkt[off + 4..off + 4 + p.software.len()].copy_from_slice(p.software.as_bytes());
    off += 4 + software_padded;

    write_tlv(&mut pkt, off, 0x0006, p.username.len() as u16); // USERNAME
    pkt[off + 4..off + 4 + p.username.len()].copy_from_slice(p.username.as_bytes());
    off += 4 + username_padded;

    write_tlv(&mut pkt, off, 0x0024, 4); // PRIORITY
    pkt[off + 4..off + 8].copy_from_slice(&p.priority.to_be_bytes());
    off += 4 + 4;

    write_tlv(&mut pkt, off, 0x802a, 8); // ICE-CONTROLLING
    pkt[off + 4..off + 12].copy_from_slice(&p.ice_controlling.to_be_bytes());
    off += 4 + 8;

    if p.with_use_candidate {
        write_tlv(&mut pkt, off, 0x0025, 0); // USE-CANDIDATE (flag)
        off += 4;
    }

    // MESSAGE-INTEGRITY over [0, off) with the length field reflecting MI only.
    let mi = hmac_sha1(p.ice_pwd, &pkt[..off]);
    write_tlv(&mut pkt, off, 0x0008, 20);
    pkt[off + 4..off + 24].copy_from_slice(&mi);
    off += MI_ATTR_LEN;

    // Patch length to include FP, then FINGERPRINT over [0, off).
    let len_full = (base_attrs_len + MI_ATTR_LEN + FP_ATTR_LEN) as u16;
    pkt[2..4].copy_from_slice(&len_full.to_be_bytes());
    let crc = crc32_ieee(&pkt[..off]) ^ 0x5354_554e;
    write_tlv(&mut pkt, off, 0x8028, 4);
    pkt[off + 4..off + 8].copy_from_slice(&crc.to_be_bytes());

    pkt
}

fn random_trans_id(rng: &mut impl RngCore) -> [u8; 12] {
    let mut id = [0u8; 12];
    rng.fill_bytes(&mut id);
    id
}

/// Generate the two STUN Binding Request datagrams of an ICE connectivity check.
pub(crate) fn generate(rng: &mut impl RngCore) -> Vec<Vec<u8>> {
    let software = SOFTWARE_POOL[(rng.next_u32() % SOFTWARE_POOL.len() as u32) as usize];
    let username = format!("{}:{}", random_token(4, 8, rng), random_token(4, 8, rng));
    let ice_pwd: Vec<u8> = random_token(22, 22, rng).into_bytes();
    let priority = rng.next_u32();
    let ice_controlling = ((rng.next_u32() as u64) << 32) | rng.next_u32() as u64;

    let first = build_binding_request(&BindingRequest {
        software,
        username: &username,
        priority,
        ice_controlling,
        trans_id: random_trans_id(rng),
        ice_pwd: &ice_pwd,
        with_use_candidate: false,
    });
    // Nomination check: fresh transaction id + USE-CANDIDATE, same credentials.
    let second = build_binding_request(&BindingRequest {
        software,
        username: &username,
        priority,
        ice_controlling,
        trans_id: random_trans_id(rng),
        ice_pwd: &ice_pwd,
        with_use_candidate: true,
    });

    vec![first, second]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn crc32_ieee_known_answer() {
        // Standard CRC-32 check value for the ASCII string "123456789".
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    }

    fn be16(b: &[u8]) -> usize {
        u16::from_be_bytes([b[0], b[1]]) as usize
    }

    /// Re-derive MESSAGE-INTEGRITY and FINGERPRINT from a built packet, proving
    /// the length-patching invariant and crypto are correct.
    fn verify_packet(pkt: &[u8], ice_pwd: &[u8], expect_use_candidate: bool) {
        assert_eq!(&pkt[0..2], &[0x00, 0x01], "Binding Request");
        assert_eq!(&pkt[4..8], &MAGIC_COOKIE);
        // Message Length covers everything after the 20-byte header.
        assert_eq!(be16(&pkt[2..4]), pkt.len() - HEADER_LEN);

        // Walk attributes, recording offsets of MI and FP.
        let mut off = HEADER_LEN;
        let mut mi_off = None;
        let mut fp_off = None;
        let mut saw_use_candidate = false;
        while off + 4 <= pkt.len() {
            let attr_type = be16(&pkt[off..]);
            let attr_len = be16(&pkt[off + 2..]);
            match attr_type {
                0x0008 => mi_off = Some(off),
                0x8028 => fp_off = Some(off),
                0x0025 => saw_use_candidate = true,
                _ => {}
            }
            off += 4 + ((attr_len + 3) & !3);
        }
        let mi_off = mi_off.expect("MESSAGE-INTEGRITY present");
        let fp_off = fp_off.expect("FINGERPRINT present");
        assert_eq!(saw_use_candidate, expect_use_candidate);

        // FINGERPRINT = CRC-32 over everything before it, XOR 0x5354554E.
        let expected_fp = crc32_ieee(&pkt[..fp_off]) ^ 0x5354_554e;
        assert_eq!(
            u32::from_be_bytes([
                pkt[fp_off + 4],
                pkt[fp_off + 5],
                pkt[fp_off + 6],
                pkt[fp_off + 7]
            ]),
            expected_fp,
            "FINGERPRINT"
        );

        // MESSAGE-INTEGRITY = HMAC-SHA1 over [0, mi_off) with the length field
        // set to base+MI (i.e. excluding the 8-byte FP attribute).
        let mut mi_view = pkt[..mi_off].to_vec();
        let len_with_mi = (pkt.len() - HEADER_LEN - FP_ATTR_LEN) as u16;
        mi_view[2..4].copy_from_slice(&len_with_mi.to_be_bytes());
        let expected_mi = hmac_sha1(ice_pwd, &mi_view);
        assert_eq!(
            &pkt[mi_off + 4..mi_off + 24],
            &expected_mi,
            "MESSAGE-INTEGRITY"
        );
    }

    #[test]
    fn generates_two_valid_binding_requests() {
        // Reproduce generate()'s credential derivation so the test knows ice_pwd.
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let _software = SOFTWARE_POOL[(rng.next_u32() % SOFTWARE_POOL.len() as u32) as usize];
        let _username = format!(
            "{}:{}",
            random_token(4, 8, &mut rng),
            random_token(4, 8, &mut rng)
        );
        let ice_pwd: Vec<u8> = random_token(22, 22, &mut rng).into_bytes();

        // Re-run with the same seed through the public API.
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let packets = generate(&mut rng);

        assert_eq!(packets.len(), 2);
        verify_packet(&packets[0], &ice_pwd, false);
        verify_packet(&packets[1], &ice_pwd, true);
        // The two checks use distinct transaction ids.
        assert_ne!(packets[0][8..20], packets[1][8..20]);
    }
}
