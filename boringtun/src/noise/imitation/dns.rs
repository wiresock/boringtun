// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! DNS query imitation, ported from wiresock's `simulate_browser_dns_resolution`.
//!
//! Emits the three standard-query datagrams a modern OS resolver sends for a
//! name — A (RFC 1035), AAAA (RFC 3596), and HTTPS/SVCB (RFC 9460) — each with a
//! fresh transaction id and the standard "recursion desired" flag. No responses
//! are synthesized.

use rand_core::RngCore;

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
            "transaction ids must all differ, got {ids:?}"
        );
    }
}
