// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! DNS query imitation, ported from wiresock's `simulate_browser_dns_resolution`.
//!
//! Emits the three standard-query datagrams a modern OS resolver sends for a
//! name — A (RFC 1035), AAAA (RFC 3596), and HTTPS/SVCB (RFC 9460) — each with a
//! fresh transaction id and the standard "recursion desired" flag. No responses
//! are synthesized.

use rand_core::RngCore;

/// A DNS message header is always 12 bytes (RFC 1035 §4.1.1).
const HEADER_LEN: usize = 12;
const QTYPE_A: u16 = 0x0001;
const QTYPE_AAAA: u16 = 0x001c;
const QTYPE_HTTPS: u16 = 0x0041;
const QCLASS_IN: u16 = 0x0001;

/// Build one standard DNS query for `domain` of the given QTYPE.
fn build_query(domain: &str, qtype: u16, rng: &mut impl RngCore) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(domain.len() + 18);

    pkt.extend_from_slice(&(rng.next_u32() as u16).to_be_bytes()); // transaction id
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: standard query, recursion desired
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // QNAME: length-prefixed labels, root-terminated.
    for label in domain.split('.') {
        let len = label.len().min(63);
        pkt.push(len as u8);
        pkt.extend_from_slice(&label.as_bytes()[..len]);
    }
    pkt.push(0x00);

    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
    pkt
}

/// End offset of an uncompressed QNAME starting at `start`, if it is well formed.
///
/// A label byte is a length only when its top two bits are `0b00`; every
/// other form -- compression pointer, extended label, reserved -- is
/// rejected rather than followed.
fn qname_end(data: &[u8], start: usize) -> Option<usize> {
    const MAX_LABEL: usize = 63;
    const MAX_QNAME: usize = 255;
    let mut pos = start;
    let mut qname_len: usize = 0;
    loop {
        let label_len = *data.get(pos)? as usize;
        // Only 0b00 is a length byte (RFC 1035 §4.1.4). Every other value of
        // the top two bits is rejected, not just the compression pointer:
        //   0b11  compression pointer
        //   0b01  extended label (RFC 2671), deprecated by RFC 6891
        //   0b10  reserved
        //
        // Kept even though it is *functionally redundant* with the MAX_LABEL
        // bound below -- every byte with a top bit set is >= 64, so the length
        // check rejects all 192 of them too, and mutating this line changes
        // nothing observable. It stays because it states which forms exist and
        // why none is followed, and because it is what still rejects a
        // compression pointer if MAX_LABEL is ever raised.
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

/// Validate `query` as a complete, well-formed standard DNS query and return
/// the offset just past its question section.
///
/// One function so the classifier and the responder cannot disagree, which is
/// the mistake the STUN pair made three times before the rules were shared.
///
/// Requires QR=0 with a standard opcode, exactly one question, a QNAME whose
/// label walk terminates exactly, and a QCLASS a real client emits -- IN(1),
/// CH(3), HS(4) or ANY(255). Trailing bytes past the question are allowed;
/// EDNS OPT records live there.
///
/// End-to-end validation rather than a header-flags check, and the difference
/// matters: AmneziaWG junk is uniformly random and roughly 3% of it passes a
/// flags-only test. At that rate a server in auto mode would eventually
/// mislabel every non-masking client as DNS.
pub(super) fn question_end(query: &[u8]) -> Option<usize> {
    if query.len() < HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if flags & 0xF800 != 0 || qdcount != 1 {
        return None;
    }
    let name_end = qname_end(query, HEADER_LEN)?;
    let end = name_end.checked_add(4)?;
    if query.len() < end {
        return None;
    }
    let qclass = u16::from_be_bytes([query[name_end + 2], query[name_end + 3]]);
    if !matches!(qclass, 1 | 3 | 4 | 255) {
        return None;
    }
    Some(end)
}

/// Build a SERVFAIL response to `query`, echoing its question section.
///
/// Returns `None` if `query` is not a well-formed standard query.
///
/// **This is imitation, not a resolver, and the difference is observable.** A
/// censor can send a query for a name under a domain it controls and watch its
/// own authoritative server: a real resolver's lookup arrives within
/// milliseconds, ours never does. One packet, no false positives, and no amount
/// of care in this function closes it -- the only fix is to actually resolve,
/// which makes the port an open resolver and a DNS amplifier. Shipping this is
/// a deliberate trade, recorded here so it is not rediscovered as a surprise.
///
/// SERVFAIL rather than a synthesised answer because it is the one RCODE that
/// requires no knowledge of the name, and a resolver returning it has said
/// nothing that can be checked against reality.
///
/// **Size**: 12-byte header plus the echoed question, which is never larger
/// than the query -- any EDNS OPT record in the request is dropped rather than
/// echoed. So this reply cannot amplify, unlike the STUN one.
#[allow(dead_code)]
pub(crate) fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    let end = question_end(query)?;

    let mut pkt = Vec::with_capacity(end);
    pkt.extend_from_slice(&query[0..2]); // transaction id, echoed

    // Byte 2 is QR | OPCODE(4) | AA | TC | RD (RFC 1035 §4.1.1).
    //
    // Copy only OPCODE and RD. Copying RD matters -- a resolver answering a
    // recursion-desired query with RD clear is a tell by itself -- but AA and
    // TC must be built fresh, not echoed: AA would claim authority over a name
    // we just failed to resolve, and TC would claim *this response* was
    // truncated when it is complete. A crafted query can set either, and
    // `question_end` does not reject them, so echoing is reachable.
    const OPCODE: u8 = 0x78;
    const RD: u8 = 0x01;
    pkt.push(0x80 | (query[2] & (OPCODE | RD)));
    pkt.push(0x80 | 0x02);

    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1, the echoed question
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    pkt.extend_from_slice(&query[HEADER_LEN..end]);

    Some(pkt)
}

/// Generate the A, AAAA and HTTPS query datagrams for `domain`.
pub(crate) fn generate(domain: &str, rng: &mut impl RngCore) -> Vec<Vec<u8>> {
    [QTYPE_A, QTYPE_AAAA, QTYPE_HTTPS]
        .iter()
        .map(|&qtype| build_query(domain, qtype, rng))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn be16(b: &[u8]) -> u16 {
        u16::from_be_bytes([b[0], b[1]])
    }

    /// Parse a query and return (qname, qtype, qclass).
    fn parse_query(pkt: &[u8]) -> (String, u16, u16) {
        assert_eq!(&pkt[2..4], &[0x01, 0x00], "flags: standard query + RD");
        assert_eq!(be16(&pkt[4..6]), 1, "QDCOUNT");
        assert_eq!(&pkt[6..12], &[0u8; 6], "no answer/authority/additional");

        let mut pos = 12;
        let mut labels = Vec::new();
        while pkt[pos] != 0 {
            let len = pkt[pos] as usize;
            pos += 1;
            labels.push(String::from_utf8_lossy(&pkt[pos..pos + len]).into_owned());
            pos += len;
        }
        pos += 1; // root label
        let qtype = be16(&pkt[pos..]);
        let qclass = be16(&pkt[pos + 2..]);
        (labels.join("."), qtype, qclass)
    }

    #[test]
    fn emits_a_aaaa_https_queries_for_domain() {
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let packets = generate("api.example.com", &mut rng);
        assert_eq!(packets.len(), 3);

        let expected_types = [QTYPE_A, QTYPE_AAAA, QTYPE_HTTPS];
        for (pkt, &want_type) in packets.iter().zip(&expected_types) {
            let (qname, qtype, qclass) = parse_query(pkt);
            assert_eq!(qname, "api.example.com");
            assert_eq!(qtype, want_type);
            assert_eq!(qclass, QCLASS_IN);
        }

        // Each query carries a distinct transaction id (all three pairwise).
        let ids: Vec<u16> = packets.iter().map(|p| be16(&p[0..2])).collect();
        assert!(
            ids[0] != ids[1] && ids[0] != ids[2] && ids[1] != ids[2],
            "transaction ids must all differ, got {:?}",
            ids
        );
    }

    /// Answering our own client's query is the realistic case: `generate`
    /// produces exactly the shape a resolver would receive.
    #[test]
    fn servfail_answers_our_own_queries() {
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        for query in generate("example.com", &mut rng) {
            let resp = servfail(&query).expect("a well-formed query must be answered");

            assert_eq!(&resp[0..2], &query[0..2], "transaction id echoed");
            assert_eq!(resp[2] & 0x80, 0x80, "QR set: this is a response");
            assert_eq!(resp[3] & 0x0F, 0x02, "RCODE = SERVFAIL");
            assert_eq!(resp[2] & 0x01, query[2] & 0x01, "RD copied from the query");
            assert_eq!(be16(&resp[4..6]), 1, "QDCOUNT = 1");
            assert_eq!(be16(&resp[6..8]), 0, "ANCOUNT = 0");

            // The question is echoed verbatim, which is what a resolver does
            // and what a client matches the response against.
            let end = question_end(&query).unwrap();
            assert_eq!(
                &resp[HEADER_LEN..],
                &query[HEADER_LEN..end],
                "question echoed"
            );
        }
    }

    /// Every non-`0b00` top-bit form is refused: compression pointer, extended
    /// label, reserved.
    ///
    /// This pins the *behaviour*, not a particular line. Narrowing the top-bits
    /// check to `== 0xC0` leaves this green, because the two checks are
    /// equivalent: any byte with a top bit set is >= 64 and the MAX_LABEL bound
    /// rejects it anyway. Enumerating all 256 values shows the two predicates
    /// agree on every one of them. Worth knowing before someone "simplifies"
    /// either check on the assumption the other covers a different case.
    #[test]
    fn every_non_length_label_form_is_rejected() {
        let mut rng = ChaCha8Rng::seed_from_u64(13);
        let good = generate("example.com", &mut rng)[0].clone();
        assert!(question_end(&good).is_some(), "control");

        for (bits, what) in [
            (0xC0u8, "compression pointer"),
            (0x40u8, "extended label (RFC 2671)"),
            (0x80u8, "reserved"),
        ] {
            let mut q = good.clone();
            q[HEADER_LEN] = bits | 0x03; // a plausible length in the low bits
            assert!(
                question_end(&q).is_none(),
                "{} must be rejected, not treated as a length",
                what
            );
            assert!(servfail(&q).is_none(), "{} must not be answered", what);
        }
    }

    /// AA and TC are built fresh, never echoed. A crafted query can set either
    /// and `question_end` does not reject them, so this is reachable rather
    /// than theoretical: AA would claim authority over a name we just failed to
    /// resolve, and TC would claim this response was truncated when it is
    /// complete. Both are wrong on a SERVFAIL and both are visible to a prober.
    #[test]
    fn aa_and_tc_are_not_echoed_from_the_query() {
        const AA: u8 = 0x04;
        const TC: u8 = 0x02;
        const RD: u8 = 0x01;

        let mut rng = ChaCha8Rng::seed_from_u64(12);
        let mut query = generate("example.com", &mut rng)[0].clone();
        query[2] |= AA | TC;
        assert_eq!(query[2] & RD, RD, "the generator sets RD");
        assert!(
            question_end(&query).is_some(),
            "a query with AA/TC set still validates, which is why this matters"
        );

        let resp = servfail(&query).unwrap();
        assert_eq!(resp[2] & AA, 0, "AA must not be echoed onto a SERVFAIL");
        assert_eq!(
            resp[2] & TC,
            0,
            "TC must not be echoed; the response is whole"
        );
        assert_eq!(resp[2] & RD, RD, "RD is still copied");
        assert_eq!(resp[2] & 0x80, 0x80, "QR still set");
    }

    /// Unlike the STUN reply, this one can never amplify: the response is the
    /// header plus the echoed question, and any EDNS OPT in the request is
    /// dropped rather than echoed.
    #[test]
    fn a_servfail_is_never_larger_than_its_query() {
        let mut rng = ChaCha8Rng::seed_from_u64(10);
        for query in generate("a-fairly-long-name.example.com", &mut rng) {
            let resp = servfail(&query).unwrap();
            assert!(
                resp.len() <= query.len(),
                "response {} > query {}",
                resp.len(),
                query.len()
            );
        }

        // With an EDNS OPT record appended, the gap widens rather than closes.
        let mut with_opt = generate("example.com", &mut rng)[0].clone();
        with_opt[11] = 1; // ARCOUNT = 1
        with_opt.extend_from_slice(&[0x00, 0x00, 0x29, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        let resp = servfail(&with_opt).unwrap();
        assert!(resp.len() < with_opt.len(), "OPT is dropped, not echoed");
    }

    /// The responder and the classifier share `question_end`, so a datagram one
    /// accepts is exactly the set the other accepts. Asserted as agreement,
    /// because agreement is the property that keeps them from drifting.
    #[test]
    fn responder_and_classifier_accept_the_same_datagrams() {
        use crate::noise::imitation::detect::{detect, Probe};

        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let good = generate("example.com", &mut rng)[0].clone();

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("well formed", good.clone()),
            ("qdcount 0", {
                let mut q = good.clone();
                q[5] = 0;
                q
            }),
            ("compression pointer in QNAME", {
                let mut q = good.clone();
                q[HEADER_LEN] = 0xC0;
                q
            }),
            ("unserved QCLASS", {
                let mut q = good.clone();
                let n = q.len();
                q[n - 1] = 0x09;
                q
            }),
            ("truncated mid-question", good[..HEADER_LEN + 2].to_vec()),
            ("response, not query", {
                let mut q = good.clone();
                q[2] |= 0x80; // QR set
                q
            }),
        ];

        for (name, q) in cases {
            let answered = servfail(&q).is_some();
            let classified = detect(&q) == Some(Probe::Dns);
            assert_eq!(
                answered, classified,
                "{name}: responder answered={answered}, classifier said DNS={classified}"
            );
        }
    }
}
