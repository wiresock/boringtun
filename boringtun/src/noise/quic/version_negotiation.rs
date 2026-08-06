// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! QUIC Version Negotiation replies, and the long-header parse they share with
//! the probe classifier.
//!
//! # When a VN packet is correct, and when it is a tell
//!
//! RFC 9000 §6.1: a server sends Version Negotiation **only** when it does not
//! support the version the client offered. That makes VN a narrow tool, and
//! using it as a general "I am a QUIC server" reply is exactly the mistake it
//! invites — answering a v1 Initial with VN declares *"I support no real QUIC
//! version"*, which is true of essentially no deployed server and is visible in
//! a single packet.
//!
//! So [`version_negotiation`] replies only when the offered version is one a
//! real server genuinely would not support: an IETF draft, or a GREASE value
//! that RFC 9000 §15 says must never be supported. A v1 or v2 Initial gets
//! **silence**, because the honest answer there is a real handshake and we
//! cannot produce one.
//!
//! The cost is that the common probe — a v1 Initial — is not answered. That is
//! deliberate: a reply that is wrong is worse than no reply, since silence is
//! what the overwhelming majority of UDP ports give and carries almost no
//! information, while a malformed VN is a positive identification.

use rand_core::RngCore;

/// RFC 9000 §17.2: a connection ID is at most 20 bytes.
pub(crate) const MAX_CID_LEN: usize = 20;

/// RFC 9000 §14.1: a client's Initial datagram must be at least 1200 bytes, and
/// a server must not act on a smaller one. Anything shorter is not an Initial a
/// real endpoint would answer.
pub(crate) const MIN_INITIAL_DATAGRAM: usize = 1200;

/// The fields of a QUIC long header that both the classifier and the responder
/// need.
///
/// One parser for both, so they cannot disagree about what counts as a long
/// header. The STUN pair drifted three times before its rules were shared and
/// the DNS pair shared them from the start; this follows the latter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LongHeader<'a> {
    pub(crate) version: u32,
    /// Destination Connection ID, as sent by the client.
    pub(crate) dcid: &'a [u8],
    /// Source Connection ID, as sent by the client.
    pub(crate) scid: &'a [u8],
}

/// Is `version` one a client would put in a real QUIC long header?
///
/// Accepted: v1 (RFC 9000), v2 (RFC 9369), IETF drafts `0xff0000xx` with
/// `xx != 0`, and the GREASE pattern `0x?a?a?a?a` (RFC 9000 §15).
///
/// A heuristic, not a guarantee — a crafted datagram can still place a matching
/// value here. That is acceptable because this never decides whether to *accept*
/// traffic, only whether to consider answering it.
pub(crate) fn is_known_version(version: u32) -> bool {
    match version {
        0x0000_0001 | 0x6b33_43cf => true,
        v if v & 0xffff_ff00 == 0xff00_0000 && v & 0xff != 0 => true,
        v if v & 0x0f0f_0f0f == 0x0a0a_0a0a => true,
        _ => false,
    }
}

/// Would a real, current QUIC server support this version?
///
/// Drafts are obsolete and GREASE is reserved precisely so that nothing
/// supports it, so both are versions for which a genuine server answers with
/// Version Negotiation.
fn is_supported_by_real_servers(version: u32) -> bool {
    matches!(version, 0x0000_0001 | 0x6b33_43cf)
}

/// Parse `data` as a QUIC long header.
///
/// Returns `None` unless the form and fixed bits are set, the version is one a
/// client would really offer, and both connection IDs fit the RFC bound *and*
/// the datagram. Every length comes from the packet, so each is checked against
/// the remaining bytes before it is used.
pub(crate) fn parse_long_header(data: &[u8]) -> Option<LongHeader<'_>> {
    // 1 first byte + 4 version + 1 dcid_len + 1 scid_len at minimum.
    if data.len() < 7 || data[0] & 0xC0 != 0xC0 {
        return None;
    }
    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    if !is_known_version(version) {
        return None;
    }

    let dcid_len = data[5] as usize;
    if dcid_len > MAX_CID_LEN {
        return None;
    }
    let dcid_end = 6usize.checked_add(dcid_len)?;
    let scid_len = *data.get(dcid_end)? as usize;
    if scid_len > MAX_CID_LEN {
        return None;
    }
    let scid_start = dcid_end.checked_add(1)?;
    let scid_end = scid_start.checked_add(scid_len)?;
    if data.len() < scid_end {
        return None;
    }

    Some(LongHeader {
        version,
        dcid: &data[6..dcid_end],
        scid: &data[scid_start..scid_end],
    })
}

/// Build a Version Negotiation reply to `initial`, or `None` if answering would
/// be wrong.
///
/// Refuses when:
/// - the datagram is not a long header we recognise;
/// - it is shorter than [`MIN_INITIAL_DATAGRAM`], because a real server does not
///   act on an undersized Initial (RFC 9000 §14.1);
/// - the offered version is one a real server supports, where VN would be a
///   false statement about ourselves.
///
/// The connection IDs are **swapped**: RFC 9000 §17.2.1 has the VN carry the
/// client's Source CID as its Destination CID and vice versa, which is how the
/// client matches the reply to its attempt. Getting this backwards produces a
/// packet every client silently drops, so it is asserted in a test rather than
/// trusted.
///
/// The seven bits after the form bit are Unused and RFC 9000 §17.2.1 has a
/// server set them to an arbitrary value — fixing them would hand an observer a
/// constant. They are randomised.
#[allow(dead_code)]
pub(crate) fn version_negotiation(initial: &[u8], rng: &mut impl RngCore) -> Option<Vec<u8>> {
    if initial.len() < MIN_INITIAL_DATAGRAM {
        return None;
    }
    let hdr = parse_long_header(initial)?;
    if is_supported_by_real_servers(hdr.version) {
        return None;
    }

    let mut pkt = Vec::with_capacity(7 + hdr.scid.len() + hdr.dcid.len() + 8);
    // Form bit set; the remaining seven bits are Unused and arbitrary.
    pkt.push(0x80 | (rng.next_u32() as u8 & 0x7F));
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Version 0 marks this as VN.

    // Swapped, per §17.2.1.
    pkt.push(hdr.scid.len() as u8);
    pkt.extend_from_slice(hdr.scid);
    pkt.push(hdr.dcid.len() as u8);
    pkt.extend_from_slice(hdr.dcid);

    // What we claim to support. A real server lists its actual versions, and
    // these are the two any current server speaks -- consistent with having
    // refused the draft or GREASE value that got us here.
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    pkt.extend_from_slice(&0x6b33_43cfu32.to_be_bytes());

    Some(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    /// A long-header Initial of `len` bytes offering `version`.
    fn initial(version: u32, dcid: &[u8], scid: &[u8], len: usize) -> Vec<u8> {
        let mut p = vec![0xC3];
        p.extend_from_slice(&version.to_be_bytes());
        p.push(dcid.len() as u8);
        p.extend_from_slice(dcid);
        p.push(scid.len() as u8);
        p.extend_from_slice(scid);
        p.resize(len.max(p.len()), 0);
        p
    }

    const DRAFT: u32 = 0xff00_001d;
    const GREASE: u32 = 0x0a0a_0a0a;
    const V1: u32 = 0x0000_0001;
    const V2: u32 = 0x6b33_43cf;

    #[test]
    fn answers_only_versions_a_real_server_would_not_support() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let (dcid, scid) = (&[1u8, 2, 3, 4][..], &[9u8, 8][..]);

        for (v, what) in [(DRAFT, "draft"), (GREASE, "GREASE")] {
            let p = initial(v, dcid, scid, MIN_INITIAL_DATAGRAM);
            assert!(
                version_negotiation(&p, &mut rng).is_some(),
                "{} is unsupported by real servers, so VN is the correct reply",
                what
            );
        }
        for (v, what) in [(V1, "v1"), (V2, "v2")] {
            let p = initial(v, dcid, scid, MIN_INITIAL_DATAGRAM);
            assert!(
                version_negotiation(&p, &mut rng).is_none(),
                "{} is supported by real servers; VN would claim otherwise",
                what
            );
        }
    }

    /// RFC 9000 §14.1. A server does not act on an undersized Initial, so
    /// answering one is a distinguisher on its own.
    #[test]
    fn an_undersized_initial_is_not_answered() {
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let (dcid, scid) = (&[1u8, 2][..], &[3u8][..]);

        let short = initial(DRAFT, dcid, scid, MIN_INITIAL_DATAGRAM - 1);
        assert!(version_negotiation(&short, &mut rng).is_none());

        let exact = initial(DRAFT, dcid, scid, MIN_INITIAL_DATAGRAM);
        assert!(version_negotiation(&exact, &mut rng).is_some());
    }

    /// §17.2.1: the VN's DCID is the client's SCID and vice versa. Backwards,
    /// every client silently drops the packet.
    #[test]
    fn connection_ids_are_swapped() {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let dcid = &[0xAA, 0xBB, 0xCC][..];
        let scid = &[0x11, 0x22][..];
        let vn = version_negotiation(&initial(DRAFT, dcid, scid, 1200), &mut rng).unwrap();

        assert_eq!(vn[0] & 0x80, 0x80, "form bit set");
        assert_eq!(&vn[1..5], &[0, 0, 0, 0], "version 0 marks a VN packet");

        let d_len = vn[5] as usize;
        assert_eq!(&vn[6..6 + d_len], scid, "VN DCID is the client's SCID");
        let s_off = 6 + d_len;
        let s_len = vn[s_off] as usize;
        assert_eq!(
            &vn[s_off + 1..s_off + 1 + s_len],
            dcid,
            "VN SCID is the client's DCID"
        );
    }

    /// The seven Unused bits are arbitrary per §17.2.1; fixing them would hand
    /// an observer a constant to key on.
    #[test]
    fn the_unused_bits_vary() {
        let p = initial(DRAFT, &[1, 2], &[3], 1200);
        let seen: std::collections::HashSet<u8> = (0..64u64)
            .map(|s| {
                let mut rng = ChaCha8Rng::seed_from_u64(s);
                version_negotiation(&p, &mut rng).unwrap()[0] & 0x7F
            })
            .collect();
        assert!(
            seen.len() > 8,
            "the Unused bits look constant across seeds: {} distinct values",
            seen.len()
        );
    }

    /// The supported-version list must not contain the version that triggered
    /// the reply -- claiming to support what we just refused is incoherent, and
    /// for GREASE it would claim support for a value RFC 9000 §15 reserves.
    #[test]
    fn the_offered_version_is_never_listed_as_supported() {
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        for v in [DRAFT, GREASE] {
            let vn = version_negotiation(&initial(v, &[1], &[2], 1200), &mut rng).unwrap();
            let list_start = 5 + 1 + 1 + 1 + 1; // header + both cid len/value
            let listed: Vec<u32> = vn[list_start..]
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            assert!(!listed.is_empty(), "a VN must advertise something");
            assert!(
                !listed.contains(&v),
                "offered {:#010x} must not appear in {:#010x?}",
                v,
                listed
            );
        }
    }

    #[test]
    fn malformed_headers_are_refused_without_panicking() {
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        // Connection-ID length beyond the RFC bound.
        let mut oversized = initial(DRAFT, &[1, 2], &[3], 1200);
        oversized[5] = 21;
        assert!(version_negotiation(&oversized, &mut rng).is_none());

        // A DCID length that runs past the datagram.
        let mut runaway = vec![0xC3];
        runaway.extend_from_slice(&DRAFT.to_be_bytes());
        runaway.push(20);
        runaway.resize(1200, 0);
        // Truncate so the declared DCID cannot fit.
        let short = &runaway[..8];
        assert!(parse_long_header(short).is_none());

        assert!(version_negotiation(&[], &mut rng).is_none());
        assert!(
            version_negotiation(&[0xC3; 1200], &mut rng).is_none(),
            "version 0xC3C3.. is unknown"
        );
    }
}
