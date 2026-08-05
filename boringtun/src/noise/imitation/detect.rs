// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Classify an inbound datagram as a DNS / QUIC / SIP / STUN probe.
//!
//! The sibling modules in [`super`] generate protocol-shaped cover traffic; this
//! one recognises it arriving. The two halves are deliberately adjacent, because
//! the property that matters is a relationship between them and is asserted by
//! the invariant table in [`crate::noise::amnezia`]'s tests: **every datagram
//! this crate emits under `ip=<proto>` is detected as `<proto>`**.
//!
//! That relationship is why a server must classify AmneziaWG *first* and only
//! then consider probe detection. Our own `fill_dns` output is a complete,
//! well-formed DNS query by construction — it frames the WireGuard ciphertext
//! inside an EDNS OPT padding option — so it satisfies [`is_plausible_dns_query`]
//! with probability 1. A server that asked "is this a probe?" before "is this
//! one of my peers?" would answer its own clients' cover traffic instead of
//! handshaking with them, and would do so *more* often the better the imitation
//! got.
//!
//! Ported from `amneziawg-proxy`'s responder, which reached these heuristics
//! empirically against real DPI probes. Nothing here sends: detection is a pure
//! function of the datagram, so it needs no device, no socket and no key, and it
//! is testable on every platform rather than only where `device` compiles.

// Phase 1 of the probe-responder work lands the detector and the invariant
// table it proves, deliberately with no caller: no hook, no config key, no
// reply path, and therefore no behaviour change to review alongside it. The
// only consumers today are this module's tests and the invariant table in
// `amnezia.rs`, so every item here is dead code in a non-test build.
//
// This allow comes off in the phase that adds the ingress hook. Scoped to the
// module rather than the crate so it cannot mask dead code anywhere else.
#![allow(dead_code)]

use super::super::amnezia::AmneziaImitationProtocol;

/// A protocol an inbound datagram was recognised as.
///
/// Deliberately not [`AmneziaImitationProtocol`], which carries a `None` variant
/// meaning "do not imitate". That is a configuration state, not a detection
/// result, and `Some(None)` would be nonsense. The two are tied together by
/// [`Probe::is`] so they cannot drift apart silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    Dns,
    Quic,
    Sip,
    Stun,
}

impl Probe {
    /// Does this detection correspond to the configured imitation protocol?
    pub(crate) fn is(self, configured: AmneziaImitationProtocol) -> bool {
        matches!(
            (self, configured),
            (Probe::Dns, AmneziaImitationProtocol::Dns)
                | (Probe::Quic, AmneziaImitationProtocol::Quic)
                | (Probe::Sip, AmneziaImitationProtocol::Sip)
                | (Probe::Stun, AmneziaImitationProtocol::Stun)
        )
    }
}

const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
/// RFC 9000 §17.2: a connection ID is at most 20 bytes.
const QUIC_MAX_CID_LEN: usize = 20;

/// Is `version` one a client would put in a real QUIC long header?
///
/// This check is what separates a genuine long header from any other protocol
/// whose leading byte happens to have the form and fixed bits set — most
/// notably a DNS query whose transaction-ID high byte lands in `0xC0..=0xFF`.
///
/// Accepted: v1 (RFC 9000), v2 (RFC 9369), IETF drafts `0xff0000xx` with
/// `xx != 0`, and the GREASE pattern `0x?a?a?a?a` (RFC 9000 §15).
///
/// A heuristic, not a guarantee — a crafted datagram can still place a matching
/// value here. That is acceptable because detection never decides whether to
/// *accept* traffic, only whether to consider answering it.
fn is_quic_version(version: u32) -> bool {
    match version {
        0x0000_0001 | 0x6b33_43cf => true,
        v if v & 0xffff_ff00 == 0xff00_0000 && v & 0xff != 0 => true,
        v if v & 0x0f0f_0f0f == 0x0a0a_0a0a => true,
        _ => false,
    }
}

/// End offset of an uncompressed QNAME starting at `start`, if it is well formed.
///
/// Rejects compression pointers: a probe carries its question inline, and
/// following a pointer would mean parsing attacker-controlled offsets.
fn dns_qname_end(data: &[u8], start: usize) -> Option<usize> {
    const MAX_LABEL: usize = 63;
    const MAX_QNAME: usize = 255;
    let mut pos = start;
    let mut qname_len: usize = 0;
    loop {
        let label_len = *data.get(pos)? as usize;
        // Top two bits set marks a compression pointer or a reserved form.
        if label_len & 0xC0 != 0 {
            return None;
        }
        if label_len == 0 {
            return Some(pos + 1);
        }
        if label_len > MAX_LABEL {
            return None;
        }
        qname_len += 1 + label_len;
        // +1 for the terminating root label.
        if qname_len + 1 > MAX_QNAME {
            return None;
        }
        pos += 1 + label_len;
    }
}

/// Is this a complete, well-formed standard DNS query?
///
/// Requires QR=0 with a standard opcode, exactly one question, a QNAME whose
/// label walk terminates exactly, and a QCLASS a real client emits — IN(1),
/// CH(3), HS(4) or ANY(255). Trailing bytes are allowed; EDNS OPT records live
/// there.
///
/// End-to-end validation rather than a header-flags check, and the difference
/// matters: AmneziaWG junk is uniformly random, and roughly 3% of it passes a
/// flags-only test. At that rate a server in auto mode would eventually
/// mislabel every non-masking client as DNS.
fn is_plausible_dns_query(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if flags & 0xF800 != 0 || qdcount != 1 {
        return false;
    }
    let Some(qname_end) = dns_qname_end(data, 12) else {
        return false;
    };
    if data.len() < qname_end + 4 {
        return false;
    }
    let qclass = u16::from_be_bytes([data[qname_end + 2], data[qname_end + 3]]);
    matches!(qclass, 1 | 3 | 4 | 255)
}

/// SIP request methods and the response prefix, longest first so a shorter
/// keyword cannot shadow a longer one.
///
/// Covers every method this crate can emit: `INVITE`/`CANCEL` from the
/// INVITE-plus-CANCEL burst, and `REGISTER`/`OPTIONS`/`SUBSCRIBE`/`NOTIFY` from
/// the pre-handshake junk packets. `SIP/` matches a *response* line, which a
/// client never sends — it is here only so the detector's view of "is this SIP"
/// matches a reader's.
const SIP_PREFIXES: [&str; 11] = [
    "SUBSCRIBE ",
    "REGISTER ",
    "OPTIONS ",
    "MESSAGE ",
    "INVITE ",
    "CANCEL ",
    "NOTIFY ",
    "INFO ",
    "ACK ",
    "BYE ",
    "SIP/",
];

/// Classify `data` as a probe, or `None` if it resembles none of the four.
///
/// Order is QUIC, STUN, DNS, SIP. The first three are mutually exclusive by
/// construction — the STUN magic cookie is checked before DNS precisely so a
/// STUN header cannot fall through into the DNS arm — and SIP is last because
/// its test is a textual prefix, the weakest evidence of the four.
pub(crate) fn detect(data: &[u8]) -> Option<Probe> {
    if data.is_empty() {
        return None;
    }

    // QUIC long header: form and fixed bits set, a recognised version, and
    // connection-ID lengths that fit both the RFC bound and the datagram.
    if data.len() >= 7 && data[0] & 0xC0 == 0xC0 {
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let dcid_len = data[5] as usize;
        if is_quic_version(version) && dcid_len <= QUIC_MAX_CID_LEN {
            let scid_len_offset = 6 + dcid_len;
            if let Some(&scid_len) = data.get(scid_len_offset) {
                let scid_len = scid_len as usize;
                if scid_len <= QUIC_MAX_CID_LEN && data.len() >= scid_len_offset + 1 + scid_len {
                    return Some(Probe::Quic);
                }
            }
        }
    }

    // STUN Binding Request (RFC 5389 / 8489): 20-byte header, top two
    // message-type bits clear, 32-bit-aligned length that accounts for the
    // whole datagram, and the magic cookie.
    let has_stun_cookie = data.len() >= 8
        && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == STUN_MAGIC_COOKIE;
    if data.len() >= 20 && has_stun_cookie {
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if msg_type & 0xC000 == 0
            && msg_type == STUN_BINDING_REQUEST
            && msg_len.is_multiple_of(4)
            && data.len() == 20 + msg_len
        {
            return Some(Probe::Stun);
        }
    }

    if !has_stun_cookie && is_plausible_dns_query(data) {
        return Some(Probe::Dns);
    }

    // Allocation-free, ASCII case-insensitive prefix match. Only the first few
    // bytes are examined, so a long datagram costs no more than a short one.
    let head = &data[..data.len().min(10)];
    if let Ok(text) = std::str::from_utf8(head) {
        if SIP_PREFIXES.iter().any(|p| {
            text.get(..p.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(p))
        }) {
            return Some(Probe::Sip);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal well-formed query for `example.com` IN A.
    fn dns_query(txid: [u8; 2]) -> Vec<u8> {
        let mut q = vec![txid[0], txid[1], 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        q
    }

    fn stun_binding_request() -> Vec<u8> {
        let mut p = vec![0x00, 0x01, 0x00, 0x00];
        p.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        p.extend_from_slice(&[0xAB; 12]); // transaction ID
        p
    }

    fn quic_initial() -> Vec<u8> {
        let mut p = vec![0xC3];
        p.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        p.push(4); // DCID len
        p.extend_from_slice(&[1, 2, 3, 4]);
        p.push(0); // SCID len
        p.extend_from_slice(&[0u8; 16]);
        p
    }

    #[test]
    fn detects_each_protocol() {
        assert_eq!(detect(&dns_query([0x12, 0x34])), Some(Probe::Dns));
        assert_eq!(detect(&stun_binding_request()), Some(Probe::Stun));
        assert_eq!(detect(&quic_initial()), Some(Probe::Quic));
        assert_eq!(detect(b"INVITE sip:a@b SIP/2.0\r\n\r\n"), Some(Probe::Sip));
        assert_eq!(detect(b"OPTIONS sip:a@b SIP/2.0\r\n\r\n"), Some(Probe::Sip));
        assert_eq!(detect(b"sip/2.0 100 Trying\r\n\r\n"), Some(Probe::Sip));
    }

    #[test]
    fn empty_and_short_datagrams_are_not_probes() {
        assert_eq!(detect(b""), None);
        assert_eq!(detect(b"\x00"), None);
        assert_eq!(detect(&[0xC0; 6]), None);
    }

    /// The regression the version check exists for: a DNS query whose
    /// transaction-ID high byte sets the QUIC long-header bits must still be
    /// DNS, not QUIC.
    #[test]
    fn dns_with_a_long_header_shaped_txid_is_not_quic() {
        for hi in [0xC0u8, 0xCF, 0xDD, 0xFF] {
            let q = dns_query([hi, 0x34]);
            assert_eq!(q[0] & 0xC0, 0xC0, "txid must set the form+fixed bits");
            assert_eq!(detect(&q), Some(Probe::Dns), "txid high byte {hi:#04x}");
        }
    }

    /// A draft version of 0 is not a real draft, and must not be accepted just
    /// because the top 24 bits match.
    #[test]
    fn quic_draft_zero_is_rejected() {
        assert!(is_quic_version(0xff00_0001));
        assert!(!is_quic_version(0xff00_0000));
        assert!(is_quic_version(0x0a0a_0a0a));
        assert!(is_quic_version(0x1a2a_3a4a), "GREASE nibble pattern");
        assert!(!is_quic_version(0x0000_0002));
    }

    /// STUN is checked before DNS so a Binding Request cannot fall through into
    /// the DNS arm, whose header offsets it would otherwise overlap.
    #[test]
    fn stun_is_not_mistaken_for_dns() {
        let s = stun_binding_request();
        assert_eq!(detect(&s), Some(Probe::Stun));
        // Same bytes with a length that does not account for the datagram is
        // neither STUN nor DNS.
        let mut bad = s.clone();
        bad[3] = 0x04;
        assert_eq!(detect(&bad), None);
    }

    #[test]
    fn malformed_dns_is_rejected() {
        // QDCOUNT = 0
        let mut q = dns_query([1, 2]);
        q[5] = 0;
        assert_eq!(detect(&q), None);
        // Compression pointer in the QNAME
        let mut q = dns_query([1, 2]);
        q[12] = 0xC0;
        assert_eq!(detect(&q), None);
        // Unserved QCLASS
        let mut q = dns_query([1, 2]);
        let n = q.len();
        q[n - 1] = 0x09;
        assert_eq!(detect(&q), None);
        // Truncated mid-QNAME
        assert_eq!(detect(&q[..14]), None);
    }

    #[test]
    fn probe_is_maps_onto_the_config_enum() {
        assert!(Probe::Dns.is(AmneziaImitationProtocol::Dns));
        assert!(Probe::Quic.is(AmneziaImitationProtocol::Quic));
        assert!(Probe::Sip.is(AmneziaImitationProtocol::Sip));
        assert!(Probe::Stun.is(AmneziaImitationProtocol::Stun));
        assert!(!Probe::Dns.is(AmneziaImitationProtocol::Stun));
        assert!(!Probe::Dns.is(AmneziaImitationProtocol::None));
    }
}
