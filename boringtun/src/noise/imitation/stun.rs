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
use std::net::SocketAddr;

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

// The response side has no caller yet -- the ingress hook that will reach it
// is the next commit. Scoped to these items rather than the module, so the
// request side stays covered by the lint.

/// What `msg` carries in place of a FINGERPRINT attribute.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fingerprint {
    /// No FINGERPRINT attribute. Nothing to echo, nothing to check.
    Absent,
    /// Present, last, four bytes, and the CRC matches.
    Valid,
    /// Present but malformed or wrong. RFC 5389 §15.5: an agent receiving a
    /// message whose FINGERPRINT is incorrect MUST discard it.
    Invalid,
}

/// Classify `msg`'s FINGERPRINT attribute.
///
/// Presence alone is not enough. A real STUN stack validates the CRC and drops
/// the message when it fails, so a responder that answers a deliberately
/// corrupted FINGERPRINT is distinguishable from a real server in one packet --
/// which is the whole thing this is trying not to be.
///
/// Parsing attacker-controlled bytes, so every step is bounds-checked and a
/// length that overruns the buffer ends the walk: a bad length is not a reason
/// to keep guessing at offsets.
///
/// `msg.len()` is the authoritative end of the message here because
/// [`binding_success`] has already checked it equals `HEADER_LEN + msg_len`.
/// Calling this on an unvalidated datagram would let trailing bytes change
/// which attribute counts as last.
#[allow(dead_code)]
fn check_fingerprint(msg: &[u8]) -> Fingerprint {
    let mut off = HEADER_LEN;
    while off + 4 <= msg.len() {
        let attr_type = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let attr_len = u16::from_be_bytes([msg[off + 2], msg[off + 3]]) as usize;

        if attr_type == 0x8028 {
            // RFC 5389 §15.5: four bytes, and the last attribute in the
            // message. Anything else is malformed rather than merely unusual.
            if attr_len != 4 || off + FP_ATTR_LEN != msg.len() {
                return Fingerprint::Invalid;
            }
            let expected = crc32_ieee(&msg[..off]) ^ 0x5354_554e;
            let got = u32::from_be_bytes([msg[off + 4], msg[off + 5], msg[off + 6], msg[off + 7]]);
            return if got == expected {
                Fingerprint::Valid
            } else {
                Fingerprint::Invalid
            };
        }

        let advance = match padded(attr_len).checked_add(4) {
            Some(a) => a,
            None => return Fingerprint::Absent,
        };
        off = match off.checked_add(advance) {
            Some(o) if o <= msg.len() => o,
            _ => return Fingerprint::Absent,
        };
    }
    Fingerprint::Absent
}

/// Upper bound on the SOFTWARE value this encoder will emit, in bytes.
///
/// Two jobs. It keeps `software.len() as u16` and the message-length cast
/// lossless by construction rather than by assumption -- the failure this
/// branch has now hit twice, where a limit was documented and never enforced.
/// And it keeps what we emit inside the spec's limit, which is expressed in
/// *characters* (fewer than 128) rather than bytes: every value we pass comes
/// from `SOFTWARE_POOL` and is short ASCII, so a 128-byte ceiling cannot exceed
/// the character limit for anything this crate produces.
///
/// Deliberately not derived from a byte figure. The character-to-byte
/// conversion depends on which UTF-8 revision the reader has in mind, and being
/// stricter than necessary on a value we choose ourselves costs nothing.
const MAX_SOFTWARE_LEN: usize = 128;

#[allow(dead_code)]
/// Write XOR-MAPPED-ADDRESS (RFC 5389 §15.2) for `client` at `off`.
///
/// The port is XORed with the top half of the magic cookie and the address with
/// the cookie itself; IPv6 continues the XOR into the transaction id, which is
/// why the id has to be passed in rather than read back from the header.
fn write_xor_mapped_address(pkt: &mut [u8], off: usize, client: SocketAddr, trans_id: &[u8; 12]) {
    let cookie = u32::from_be_bytes(MAGIC_COOKIE);
    let x_port = client.port() ^ (cookie >> 16) as u16;

    match client {
        SocketAddr::V4(v4) => {
            write_tlv(pkt, off, 0x0020, 8);
            pkt[off + 4] = 0;
            pkt[off + 5] = 0x01; // IPv4
            pkt[off + 6..off + 8].copy_from_slice(&x_port.to_be_bytes());
            let x_addr = u32::from(*v4.ip()) ^ cookie;
            pkt[off + 8..off + 12].copy_from_slice(&x_addr.to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            write_tlv(pkt, off, 0x0020, 20);
            pkt[off + 4] = 0;
            pkt[off + 5] = 0x02; // IPv6
            pkt[off + 6..off + 8].copy_from_slice(&x_port.to_be_bytes());
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE);
            key[4..].copy_from_slice(trans_id);
            let addr = v6.ip().octets();
            for i in 0..16 {
                pkt[off + 8 + i] = addr[i] ^ key[i];
            }
        }
    }
}

#[allow(dead_code)]
/// Attribute size of XOR-MAPPED-ADDRESS for this address family.
fn xor_mapped_len(client: SocketAddr) -> usize {
    4 + if client.is_ipv4() { 8 } else { 20 }
}

#[allow(dead_code)]
/// Build a Binding Success Response to `request`, reporting `client` as the
/// reflexive address.
///
/// Returns `None` if `request` is not a Binding Request this should answer.
///
/// **Presents as an unauthenticated public STUN server**, which is the
/// deployment that answers Binding Requests from strangers at all — the kind a
/// prober would expect to find. So a MESSAGE-INTEGRITY attribute in the request
/// is ignored rather than answered with 401: we hold no credential, and a
/// server that demanded one would refuse every unauthenticated check, which no
/// public STUN server does.
///
/// FINGERPRINT is echoed when the request carries a *valid* one, because RFC
/// 5389 §15.5 requires it and its absence is a one-attribute tell. A request
/// whose FINGERPRINT is present but wrong gets no answer at all: a real stack
/// discards such a message, so replying would distinguish us in one packet.
///
/// **Size**: 20-byte header + 12 (IPv4) or 24 (IPv6) + SOFTWARE + 8 if
/// FINGERPRINT. Against a minimal 20-byte Binding Request that is larger than
/// the request; against a real ICE connectivity check — which carries SOFTWARE,
/// USERNAME, PRIORITY, ICE-CONTROLLING, MESSAGE-INTEGRITY and FINGERPRINT — it
/// is smaller. The caller decides whether a given ratio is acceptable; this
/// function does not send.
pub(crate) fn binding_success(
    request: &[u8],
    client: SocketAddr,
    software: &str,
) -> Option<Vec<u8>> {
    if request.len() < HEADER_LEN {
        return None;
    }
    if u16::from_be_bytes([request[0], request[1]]) != 0x0001 {
        return None;
    }
    if request[4..8] != MAGIC_COOKIE {
        return None;
    }
    // The length field is authoritative, and a real agent checks it: RFC 8489
    // §6.3 has a receiver verify "that the message length is sensible" before
    // anything else. Without this, a datagram whose length disagrees with its
    // size gets answered where a real server discards it -- and it would also
    // move where `check_fingerprint` believes the message ends, changing what
    // counts as the last attribute. `detect` already requires this exact
    // equality for STUN; the responder was the looser of the two.
    let msg_len = u16::from_be_bytes([request[2], request[3]]) as usize;
    if request.len() != HEADER_LEN + msg_len {
        return None;
    }
    let mut trans_id = [0u8; 12];
    trans_id.copy_from_slice(&request[8..20]);

    // A wrong FINGERPRINT means a real server would have discarded this, so
    // answering it is a distinguisher. Silence is the correct imitation.
    let echo_fingerprint = match check_fingerprint(request) {
        Fingerprint::Absent => false,
        Fingerprint::Valid => true,
        Fingerprint::Invalid => return None,
    };

    // Keeps every `as u16` below lossless. A truncated SOFTWARE length would
    // frame the attribute wrongly and the whole message with it.
    if software.len() > MAX_SOFTWARE_LEN {
        return None;
    }
    let software_padded = padded(software.len());
    let attrs_len = xor_mapped_len(client)
        + (4 + software_padded)
        + if echo_fingerprint { FP_ATTR_LEN } else { 0 };

    // Zero-initialised: attribute padding bytes must be zero for the CRC.
    // `attrs_len` is bounded by MAX_SOFTWARE_LEN plus two fixed attributes, so
    // it fits u16 by construction -- asserted rather than assumed.
    debug_assert!(attrs_len <= u16::MAX as usize);
    let mut pkt = vec![0u8; HEADER_LEN + attrs_len];
    pkt[0..2].copy_from_slice(&0x0101u16.to_be_bytes()); // Binding Success
    pkt[2..4].copy_from_slice(&(attrs_len as u16).to_be_bytes());
    pkt[4..8].copy_from_slice(&MAGIC_COOKIE);
    pkt[8..20].copy_from_slice(&trans_id);

    let mut off = HEADER_LEN;
    write_xor_mapped_address(&mut pkt, off, client, &trans_id);
    off += xor_mapped_len(client);

    write_tlv(&mut pkt, off, 0x8022, software.len() as u16); // SOFTWARE
    pkt[off + 4..off + 4 + software.len()].copy_from_slice(software.as_bytes());
    off += 4 + software_padded;

    if echo_fingerprint {
        // RFC 5389 §15.5: computed with the length field already covering the
        // FINGERPRINT attribute, which it does -- `attrs_len` included it.
        let crc = crc32_ieee(&pkt[..off]) ^ 0x5354_554e;
        write_tlv(&mut pkt, off, 0x8028, 4);
        pkt[off + 4..off + 8].copy_from_slice(&crc.to_be_bytes());
    }

    Some(pkt)
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

    fn parse_attrs(msg: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut off = HEADER_LEN;
        while off + 4 <= msg.len() {
            let t = u16::from_be_bytes([msg[off], msg[off + 1]]);
            let l = u16::from_be_bytes([msg[off + 2], msg[off + 3]]) as usize;
            let end = off + 4 + l;
            if end > msg.len() {
                break;
            }
            out.push((t, msg[off + 4..end].to_vec()));
            off += 4 + padded(l);
        }
        out
    }

    /// Answering our own client's ICE check is the realistic case: the request
    /// carries FINGERPRINT, so the response must too.
    #[test]
    fn binding_success_answers_our_own_connectivity_check() {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let request = &generate(&mut rng)[0];
        let client: SocketAddr = "203.0.113.7:51820".parse().unwrap();

        let resp = binding_success(request, client, "Chromium").expect("must answer");

        assert_eq!(&resp[0..2], &0x0101u16.to_be_bytes(), "Binding Success");
        assert_eq!(&resp[4..8], &MAGIC_COOKIE, "magic cookie");
        assert_eq!(&resp[8..20], &request[8..20], "transaction id echoed");
        assert_eq!(
            u16::from_be_bytes([resp[2], resp[3]]) as usize,
            resp.len() - HEADER_LEN,
            "length field covers exactly the attributes"
        );

        let attrs = parse_attrs(&resp);
        let types: Vec<u16> = attrs.iter().map(|(t, _)| *t).collect();
        assert!(types.contains(&0x0020), "XOR-MAPPED-ADDRESS present");
        assert!(types.contains(&0x8022), "SOFTWARE present");
        assert!(
            types.contains(&0x8028),
            "FINGERPRINT must be echoed when the request carries one (RFC 5389 s15.5)"
        );
    }

    /// The reflexive address is the point of the response: a client reads its
    /// own public address out of it, so a wrong XOR is not cosmetic.
    #[test]
    fn xor_mapped_address_decodes_back_to_the_client() {
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        let request = &generate(&mut rng)[0];

        for addr in ["198.51.100.42:1234", "[2001:db8::dead:beef]:4321"] {
            let client: SocketAddr = addr.parse().unwrap();
            let resp = binding_success(request, client, "Mozilla").unwrap();
            let attrs = parse_attrs(&resp);
            let (_, v) = attrs.iter().find(|(t, _)| *t == 0x0020).expect("XMA");

            let cookie = u32::from_be_bytes(MAGIC_COOKIE);
            let port = u16::from_be_bytes([v[2], v[3]]) ^ (cookie >> 16) as u16;
            assert_eq!(port, client.port(), "port for {addr}");

            match client {
                SocketAddr::V4(v4) => {
                    assert_eq!(v[1], 0x01, "family");
                    let x = u32::from_be_bytes([v[4], v[5], v[6], v[7]]);
                    assert_eq!(std::net::Ipv4Addr::from(x ^ cookie), *v4.ip());
                }
                SocketAddr::V6(v6) => {
                    assert_eq!(v[1], 0x02, "family");
                    let mut key = [0u8; 16];
                    key[..4].copy_from_slice(&MAGIC_COOKIE);
                    key[4..].copy_from_slice(&resp[8..20]);
                    let mut out = [0u8; 16];
                    for i in 0..16 {
                        out[i] = v[4 + i] ^ key[i];
                    }
                    assert_eq!(std::net::Ipv6Addr::from(out), *v6.ip());
                }
            }
        }
    }

    /// A FINGERPRINT that is present but wrong is a worse tell than one that is
    /// absent: any real STUN stack validates it and drops the message. Checked
    /// with the same CRC the request-side test uses.
    #[test]
    fn echoed_fingerprint_validates() {
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let request = &generate(&mut rng)[0];

        for addr in ["203.0.113.9:1", "[2001:db8::1]:65535"] {
            let client: SocketAddr = addr.parse().unwrap();
            let resp = binding_success(request, client, "PJSIP 2.13.0").unwrap();

            let fp_off = resp.len() - FP_ATTR_LEN;
            assert_eq!(
                be16(&resp[fp_off..]),
                0x8028,
                "FINGERPRINT must be the last attribute"
            );
            let expected = crc32_ieee(&resp[..fp_off]) ^ 0x5354_554e;
            let got = u32::from_be_bytes([
                resp[fp_off + 4],
                resp[fp_off + 5],
                resp[fp_off + 6],
                resp[fp_off + 7],
            ]);
            assert_eq!(got, expected, "FINGERPRINT CRC for {addr}");
        }
    }

    /// A bare Binding Request without FINGERPRINT must not gain one: echoing an
    /// attribute the peer did not send is as much a tell as omitting one it did.
    #[test]
    fn fingerprint_is_echoed_only_when_requested() {
        let mut bare = vec![0u8; HEADER_LEN];
        bare[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        bare[2..4].copy_from_slice(&0u16.to_be_bytes()); // no attributes
        bare[4..8].copy_from_slice(&MAGIC_COOKIE);
        bare[8..20].copy_from_slice(&[0xAB; 12]);

        let client: SocketAddr = "192.0.2.1:9999".parse().unwrap();
        let resp = binding_success(&bare, client, "libnice 0.1.21").unwrap();
        let types: Vec<u16> = parse_attrs(&resp).iter().map(|(t, _)| *t).collect();
        assert!(!types.contains(&0x8028), "no FINGERPRINT was requested");
    }

    /// A real STUN stack validates FINGERPRINT and discards the message when it
    /// fails (RFC 5389 §15.5). Answering a deliberately corrupted one would
    /// distinguish us from a real server in a single packet, which is precisely
    /// what a prober is looking for.
    #[test]
    fn a_corrupt_fingerprint_gets_no_answer() {
        let mut rng = ChaCha8Rng::seed_from_u64(21);
        let request = generate(&mut rng)[0].clone();
        let client: SocketAddr = "203.0.113.5:443".parse().unwrap();

        // Intact: answered, and the request-side FP really is valid.
        assert_eq!(check_fingerprint(&request), Fingerprint::Valid);
        assert!(binding_success(&request, client, "Chromium").is_some());

        // One bit flipped in the CRC: a real server drops it, so must we.
        let mut corrupt = request.clone();
        let n = corrupt.len();
        corrupt[n - 1] ^= 0x01;
        assert_eq!(check_fingerprint(&corrupt), Fingerprint::Invalid);
        assert!(
            binding_success(&corrupt, client, "Chromium").is_none(),
            "a wrong FINGERPRINT must produce silence, not a reply"
        );

        // Present but not last: also malformed per §15.5.
        let mut trailing = request.clone();
        trailing.extend_from_slice(&[0u8; 4]);
        assert_eq!(check_fingerprint(&trailing), Fingerprint::Invalid);
        assert!(binding_success(&trailing, client, "Chromium").is_none());
    }

    /// `software.len()` and the message length are cast to `u16`. An oversized
    /// value would truncate and frame the packet wrongly, so it is refused --
    /// the same shape as the budget rate that was documented but unenforced.
    #[test]
    fn an_oversized_software_value_is_refused() {
        let mut rng = ChaCha8Rng::seed_from_u64(22);
        let request = &generate(&mut rng)[0];
        let client: SocketAddr = "192.0.2.8:1".parse().unwrap();

        let at_limit = "s".repeat(MAX_SOFTWARE_LEN);
        assert!(binding_success(request, client, &at_limit).is_some());

        let over = "s".repeat(MAX_SOFTWARE_LEN + 1);
        assert!(
            binding_success(request, client, &over).is_none(),
            "an oversized SOFTWARE must be refused, not silently truncated"
        );
    }

    /// RFC 8489 §6.3 has a receiver check "that the message length is sensible"
    /// before anything else, so a datagram whose length field disagrees with its
    /// size is discarded by a real agent. Answering one would be a distinguisher,
    /// and it would also move where `check_fingerprint` thinks the message ends.
    ///
    /// `detect` already required this exact equality for STUN; the responder was
    /// the looser of the two, which is the wrong way round.
    ///
    /// Built **without** a FINGERPRINT on purpose. My first version of this test
    /// used a real ICE check and passed even with the length validation removed,
    /// because the FINGERPRINT "must be last" rule caught both cases first. With
    /// no FINGERPRINT present, only the length check can reject these.
    #[test]
    fn a_message_length_that_disagrees_with_the_datagram_gets_no_answer() {
        let client: SocketAddr = "198.51.100.3:5060".parse().unwrap();

        // A well-framed bare Binding Request: no attributes, length 0.
        let mut bare = vec![0u8; HEADER_LEN];
        bare[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        bare[2..4].copy_from_slice(&0u16.to_be_bytes());
        bare[4..8].copy_from_slice(&MAGIC_COOKIE);
        bare[8..20].copy_from_slice(&[0x5A; 12]);
        assert_eq!(
            check_fingerprint(&bare),
            Fingerprint::Absent,
            "no FP to hide behind"
        );
        assert!(
            binding_success(&bare, client, "Chromium").is_some(),
            "control"
        );

        // Trailing byte: longer than the header declares.
        let mut trailing = bare.clone();
        trailing.push(0);
        assert!(
            binding_success(&trailing, client, "Chromium").is_none(),
            "a datagram longer than its declared length must be discarded"
        );

        // Length field overstates a payload that is not there.
        let mut overstated = bare.clone();
        overstated[2..4].copy_from_slice(&8u16.to_be_bytes());
        assert!(
            binding_success(&overstated, client, "Chromium").is_none(),
            "a length field larger than the datagram must be discarded"
        );
    }

    #[test]
    fn refuses_what_is_not_a_binding_request() {
        let client: SocketAddr = "192.0.2.1:1".parse().unwrap();
        // Too short.
        assert!(binding_success(&[0u8; 19], client, "x").is_none());
        // Right length, wrong message type (a Binding *Success*, not a request).
        let mut resp_shaped = vec![0u8; HEADER_LEN];
        resp_shaped[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        resp_shaped[4..8].copy_from_slice(&MAGIC_COOKIE);
        assert!(
            binding_success(&resp_shaped, client, "x").is_none(),
            "answering our own response shape would be a reflection loop"
        );
        // Right type, no magic cookie.
        let mut no_cookie = vec![0u8; HEADER_LEN];
        no_cookie[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        assert!(binding_success(&no_cookie, client, "x").is_none());
    }

    /// `check_fingerprint` walks attacker-controlled bytes; a length that
    /// overruns the buffer must end the walk rather than wrap or index out of
    /// bounds.
    #[test]
    fn attribute_walk_survives_malformed_lengths() {
        let client: SocketAddr = "192.0.2.1:1".parse().unwrap();
        let mut m = vec![0u8; HEADER_LEN + 8];
        m[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        // Header length is correct -- 8 bytes of attributes follow. It is the
        // *attribute* length that is malformed, which is the thing under test;
        // a wrong header length is rejected earlier and would never reach the
        // attribute walk.
        m[2..4].copy_from_slice(&8u16.to_be_bytes());
        m[4..8].copy_from_slice(&MAGIC_COOKIE);
        // An attribute claiming 0xFFFF bytes inside a 28-byte datagram.
        m[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&0x0006u16.to_be_bytes());
        m[HEADER_LEN + 2..HEADER_LEN + 4].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(binding_success(&m, client, "x").is_some(), "must not panic");
    }
}
