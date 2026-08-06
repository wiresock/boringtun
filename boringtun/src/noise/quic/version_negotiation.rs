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

/// RFC 9000 §17.2: a connection ID is at most 20 bytes, and an endpoint that
/// receives a longer long header for such a version MUST drop the packet.
///
/// Named for the document that defines it rather than for a single version,
/// because it governs **v1 and v2 alike**. RFC 9369 §3 changes only the version
/// field, the long-header packet types and the crypto parameters, and is
/// otherwise explicit that "QUIC version 2 endpoints MUST implement the QUIC
/// version 1 specification", so v2 inherits this bound. That is why
/// [`parse_long_header`] applies it to both — matching
/// [`REAL_SERVER_VERSIONS`], not a v1-only test.
///
/// It is not applied to any other version, and that is the point. RFC 8999 §5.1
/// gives every other version the full 0..=255 the 8-bit length field can
/// express, RFC 9000 §17.2 asks servers to "be able to read longer connection
/// IDs from other QUIC versions" precisely so they can form a Version
/// Negotiation packet, and §17.2.1 makes it normative: "Version-specific rules
/// for the connection ID therefore MUST NOT influence a decision about whether
/// to send a Version Negotiation packet." Enforcing 20 bytes unconditionally
/// would apply it to *exactly* the versions this module answers, since v1 and
/// v2 are refused before a reply is built.
pub(crate) const RFC9000_MAX_CID_LEN: usize = 20;

/// RFC 9000 §14.1: a client's Initial datagram must be at least 1200 bytes, and
/// a server must not act on a smaller one (§5.2.2: "Servers MUST drop smaller
/// packets that specify unsupported versions"). Anything shorter is not an
/// Initial a real endpoint would answer.
pub(crate) const MIN_INITIAL_DATAGRAM: usize = 1200;

/// The versions a real, current QUIC server speaks: v1 (RFC 9000) and v2
/// (RFC 9369).
///
/// One table, read by all three places that need it — the predicate that
/// recognises a plausible version, the predicate that refuses to answer a
/// version a real server supports, and the Supported Version list a reply
/// advertises. Three copies of the same two constants could disagree, and a VN
/// that advertises a version it also refuses is a self-contradictory packet.
pub(crate) const REAL_SERVER_VERSIONS: [u32; 2] = [0x0000_0001, 0x6b33_43cf];

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
/// This check is also what separates a genuine long header from any other
/// protocol whose leading byte happens to have the form and fixed bits set —
/// most notably a DNS query whose transaction-ID high byte lands in
/// `0xC0..=0xFF`, which is why [`super::super::imitation::detect`] leans on it.
/// Widening it to accept unknown versions would reintroduce that false
/// positive.
///
/// A heuristic, not a guarantee — a crafted datagram can still place a matching
/// value here. That is acceptable because this never decides whether to *accept*
/// traffic, only whether to consider answering it.
pub(crate) fn is_known_version(version: u32) -> bool {
    match version {
        v if is_supported_by_real_servers(v) => true,
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
    REAL_SERVER_VERSIONS.contains(&version)
}

/// Parse `data` as a QUIC long header.
///
/// Returns `None` unless the form and fixed bits are set, the version is one a
/// client would really offer, and both connection IDs fit their version's bound
/// *and* the datagram. Every length comes from the packet, so each is checked
/// against the remaining bytes before it is used — the two slices below are only
/// reachable once their end offset has been compared against `data.len()`.
pub(crate) fn parse_long_header(data: &[u8]) -> Option<LongHeader<'_>> {
    // 1 first byte + 4 version + 1 dcid_len + 1 scid_len at minimum. This is
    // what makes the direct `data[1..=5]` reads below safe.
    if data.len() < 7 || data[0] & 0xC0 != 0xC0 {
        return None;
    }
    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    if !is_known_version(version) {
        return None;
    }
    // See [`RFC9000_MAX_CID_LEN`]: the 20-byte cap is a version 1 rule, and applying
    // it to a draft or GREASE version would gate the VN decision on a
    // version-specific rule that RFC 9000 §17.2.1 says MUST NOT gate it.
    let capped = is_supported_by_real_servers(version);

    let dcid_len = data[5] as usize;
    if capped && dcid_len > RFC9000_MAX_CID_LEN {
        return None;
    }
    let dcid_end = 6usize.checked_add(dcid_len)?;
    let scid_len = *data.get(dcid_end)? as usize;
    if capped && scid_len > RFC9000_MAX_CID_LEN {
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
/// The seven bits after the form bit are Unused, and RFC 9000 §17.2.1 has a
/// server set them to an arbitrary value — fixing them would hand an observer a
/// constant. Six of them are randomised. The seventh, `0x40`, is **set**: the
/// same section says "servers SHOULD set the most significant bit of this field
/// (0x40) to 1 so that Version Negotiation packets appear to have the Fixed Bit
/// field", and errata 7578 makes that the default rather than a special case.
/// With `0x40` clear, a receiver demultiplexing a shared UDP port per RFC 7983 /
/// RFC 9443 routes the reply into the RTP/RTCP bucket instead of QUIC.
#[allow(dead_code)]
pub(crate) fn version_negotiation(initial: &[u8], rng: &mut impl RngCore) -> Option<Vec<u8>> {
    if initial.len() < MIN_INITIAL_DATAGRAM {
        return None;
    }
    let hdr = parse_long_header(initial)?;
    if is_supported_by_real_servers(hdr.version) {
        return None;
    }

    let mut pkt =
        Vec::with_capacity(7 + hdr.scid.len() + hdr.dcid.len() + 4 * REAL_SERVER_VERSIONS.len());
    // Form bit and the apparent Fixed Bit set; the other six are arbitrary.
    pkt.push(0xC0 | (rng.next_u32() as u8 & 0x3F));
    pkt.extend_from_slice(&0u32.to_be_bytes()); // Version 0 marks this as VN.

    // Swapped, per §17.2.1. Both lengths came from a u8 in `initial`, so the
    // casts round-trip exactly whatever the client declared.
    pkt.push(hdr.scid.len() as u8);
    pkt.extend_from_slice(hdr.scid);
    pkt.push(hdr.dcid.len() as u8);
    pkt.extend_from_slice(hdr.dcid);

    // What we claim to support: the same table `is_supported_by_real_servers`
    // reads, so the list can never advertise a version we would answer with VN.
    for version in REAL_SERVER_VERSIONS {
        pkt.extend_from_slice(&version.to_be_bytes());
    }

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

    /// The RFC values themselves, as literals. Structure keeps the three uses of
    /// [`REAL_SERVER_VERSIONS`] consistent; only a literal here can keep them
    /// *right*, because deriving a wrong constant everywhere derives it wrongly.
    #[test]
    fn the_version_numbers_are_the_ones_the_rfcs_assign() {
        assert_eq!(V1, 0x0000_0001, "RFC 9000 §15: QUIC v1");
        assert_eq!(V2, 0x6b33_43cf, "RFC 9369 §3.1: QUIC v2");
        assert_eq!(REAL_SERVER_VERSIONS, [V1, V2]);
        assert_eq!(
            MIN_INITIAL_DATAGRAM, 1200,
            "RFC 9000 §14.1: the smallest allowed maximum datagram size"
        );
        assert_eq!(
            RFC9000_MAX_CID_LEN, 20,
            "RFC 9000 §17.2: the version 1 connection-ID bound"
        );
    }

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

    /// RFC 9000 §14.1 / §5.2.2. A server does not act on an undersized Initial,
    /// so answering one is a distinguisher on its own.
    ///
    /// The sizes are literals, not [`MIN_INITIAL_DATAGRAM`]: 1200 *is* the
    /// claim, and written symbolically the assertion would move with the
    /// constant, so lowering it would leave this green while the responder
    /// answered datagrams a real server ignores.
    #[test]
    fn an_undersized_initial_is_not_answered() {
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let (dcid, scid) = (&[1u8, 2][..], &[3u8][..]);

        let short = initial(DRAFT, dcid, scid, 1199);
        assert!(version_negotiation(&short, &mut rng).is_none());

        let exact = initial(DRAFT, dcid, scid, 1200);
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

    /// Walk a VN packet's connection IDs and return the Supported Version list,
    /// derived from the length bytes rather than restated as an offset -- a
    /// hardcoded `list_start` is correct only for the CID lengths the test
    /// happens to use, and lands mid-CID for any other, where `chunks_exact`
    /// silently reads connection-ID bytes as version numbers.
    fn supported_versions(vn: &[u8]) -> Vec<u32> {
        let d_len = vn[5] as usize;
        let s_off = 6 + d_len;
        let list_start = s_off + 1 + vn[s_off] as usize;
        vn[list_start..]
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    /// Six of the Unused bits are arbitrary per §17.2.1; fixing them would hand
    /// an observer a constant to key on. The seventh, `0x40`, is not arbitrary:
    /// the same section has a server set it so the packet appears to carry the
    /// Fixed Bit, and with it clear an RFC 7983 / RFC 9443 demultiplexer routes
    /// the reply to RTP/RTCP instead of QUIC.
    #[test]
    fn the_fixed_bit_is_set_and_the_other_unused_bits_vary() {
        let p = initial(DRAFT, &[1, 2], &[3], 1200);
        let first_bytes: Vec<u8> = (0..64u64)
            .map(|s| {
                let mut rng = ChaCha8Rng::seed_from_u64(s);
                version_negotiation(&p, &mut rng).unwrap()[0]
            })
            .collect();

        for (seed, b) in first_bytes.iter().enumerate() {
            assert_eq!(
                b & 0xC0,
                0xC0,
                "seed {seed}: form bit and the apparent Fixed Bit must both be set, got {b:#04x}"
            );
        }

        // Every one of the six arbitrary bits must be seen both ways, not merely
        // "enough distinct values" -- a count threshold passes while whole bits
        // stay pinned.
        for bit in 0..6u8 {
            let mask = 1u8 << bit;
            assert!(
                first_bytes.iter().any(|b| b & mask != 0)
                    && first_bytes.iter().any(|b| b & mask == 0),
                "Unused bit {:#04x} is constant across 64 seeds",
                mask
            );
        }
    }

    /// The supported-version list must not contain the version that triggered
    /// the reply -- claiming to support what we just refused is incoherent, and
    /// for GREASE it would claim support for a value RFC 9000 §15 reserves.
    ///
    /// Also pins the emitted bytes themselves. Sharing [`REAL_SERVER_VERSIONS`]
    /// makes the three uses consistent; only asserting the literals here makes
    /// them correct.
    #[test]
    fn the_offered_version_is_never_listed_as_supported() {
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        for v in [DRAFT, GREASE] {
            for (dcid, scid) in [
                (&[1u8][..], &[2u8][..]),
                (&[1u8, 2, 3, 4][..], &[9u8, 8][..]),
            ] {
                let vn = version_negotiation(&initial(v, dcid, scid, 1200), &mut rng).unwrap();
                let listed = supported_versions(&vn);
                assert_eq!(
                    listed,
                    vec![0x0000_0001, 0x6b33_43cf],
                    "a VN must advertise exactly QUIC v1 and v2"
                );
                assert!(
                    !listed.contains(&v),
                    "offered {:#010x} must not appear in {:#010x?}",
                    v,
                    listed
                );
            }
        }
    }

    /// RFC 9000 §6.1: "An endpoint MUST NOT send a Version Negotiation packet in
    /// response to receiving a Version Negotiation packet." Our own reply must
    /// therefore never look like a probe to us -- otherwise two peers on the
    /// same port would answer each other forever once the ingress hook lands.
    /// The STUN pair pins the same property (`stun::binding_success` refuses its
    /// own response shape).
    #[test]
    fn our_own_reply_is_not_a_probe() {
        let mut rng = ChaCha8Rng::seed_from_u64(6);
        let vn = version_negotiation(&initial(DRAFT, &[1, 2, 3], &[4, 5], 1200), &mut rng).unwrap();

        assert!(
            parse_long_header(&vn).is_none(),
            "version 0 is not a version any client offers, so a VN is not a long header we answer"
        );
        let mut padded = vn.clone();
        padded.resize(1200, 0);
        assert!(
            version_negotiation(&padded, &mut rng).is_none(),
            "answering our own reply would be a reflection loop"
        );
    }

    /// RFC 9000 §17.2 caps a connection ID at 20 bytes *in version 1*, and
    /// §17.2.1 says version-specific connection-ID rules "MUST NOT influence a
    /// decision about whether to send a Version Negotiation packet". So the cap
    /// is enforced for v1/v2 and not for the draft and GREASE versions this
    /// module actually answers.
    #[test]
    fn the_connection_id_cap_applies_only_to_the_version_that_defines_it() {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let long_cid = [0xEE; 21];

        for v in [V1, V2] {
            let p = initial(v, &long_cid, &[3], 1200);
            assert_eq!(
                parse_long_header(&p),
                None,
                "{v:#010x}: a 21-byte DCID exceeds the RFC 9000 bound, which v2 inherits"
            );
            let p = initial(v, &[3], &long_cid, 1200);
            assert_eq!(parse_long_header(&p), None, "{v:#010x}: likewise the SCID");
        }

        // Both directions: the cap must be lifted for the DCID and the SCID
        // independently, and the long connection ID must survive the swap.
        for v in [DRAFT, GREASE] {
            let vn = version_negotiation(&initial(v, &long_cid, &[3], 1200), &mut rng)
                .unwrap_or_else(|| {
                    panic!("{:#010x}: a 21-byte DCID must not suppress the reply", v)
                });
            let s_off = 6 + vn[5] as usize;
            assert_eq!(
                &vn[s_off + 1..s_off + 1 + vn[s_off] as usize],
                &long_cid,
                "{v:#010x}: the 21-byte DCID must come back as the reply's SCID"
            );

            let vn = version_negotiation(&initial(v, &[3], &long_cid, 1200), &mut rng)
                .unwrap_or_else(|| {
                    panic!("{:#010x}: a 21-byte SCID must not suppress the reply", v)
                });
            let d_len = vn[5] as usize;
            assert_eq!(
                &vn[6..6 + d_len],
                &long_cid,
                "{v:#010x}: the 21-byte SCID must come back as the reply's DCID"
            );
        }
    }

    /// Every length in a long header is attacker-controlled, and two of them
    /// bound slices. These cases are aimed at [`parse_long_header`] directly:
    /// routed through [`version_negotiation`] the 1200-byte floor rejects the
    /// short ones first, so the assertion would pass without the parser being
    /// reached at all.
    #[test]
    fn malformed_headers_are_refused_without_panicking() {
        // Too short to hold the fields the parser reads unconditionally. Each of
        // these would index out of bounds if the `data.len() < 7` gate moved.
        assert!(parse_long_header(&[]).is_none());
        for n in 1..7usize {
            let mut truncated = vec![0xC3];
            truncated.extend_from_slice(&DRAFT.to_be_bytes());
            truncated.extend_from_slice(&[0, 0]);
            truncated.truncate(n);
            assert!(
                parse_long_header(&truncated).is_none(),
                "a {}-byte long header cannot carry both connection-ID lengths",
                n
            );
        }

        // A DCID length that runs past the datagram: `data.get(dcid_end)`.
        let mut runaway = vec![0xC3];
        runaway.extend_from_slice(&DRAFT.to_be_bytes());
        runaway.push(20);
        runaway.resize(8, 0);
        assert!(parse_long_header(&runaway).is_none());

        // An SCID length that runs past the datagram: the last bounds check, and
        // the one guarding `&data[scid_start..scid_end]`.
        let mut scid_overruns = initial(DRAFT, &[1, 2], &[3, 4, 5], 0);
        scid_overruns.truncate(scid_overruns.len() - 1);
        assert!(
            parse_long_header(&scid_overruns).is_none(),
            "a declared SCID that does not fit must be refused, not sliced"
        );

        // The version 1 connection-ID bound, on the version that defines it.
        let mut oversized = initial(V1, &[1, 2], &[3], 1200);
        oversized[5] = 21;
        assert!(parse_long_header(&oversized).is_none());

        // The form and fixed bits: a long header must have both.
        let mut no_fixed_bit = initial(DRAFT, &[1, 2], &[3], 1200);
        no_fixed_bit[0] = 0x83;
        assert!(
            parse_long_header(&no_fixed_bit).is_none(),
            "0x40 clear is not a long header this parser accepts"
        );

        let mut rng = ChaCha8Rng::seed_from_u64(5);
        assert!(version_negotiation(&[], &mut rng).is_none());
        assert!(
            version_negotiation(&[0xC3; 1200], &mut rng).is_none(),
            "version 0xC3C3.. is unknown"
        );
    }
}
