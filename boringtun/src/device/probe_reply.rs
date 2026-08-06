// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Decide whether to answer an unauthenticated datagram, and with what.
//!
//! This is the policy layer between the classifier, the three reply generators
//! and the ingress path. It exists so the hook in [`super`] stays three lines
//! and every decision here is testable without a TUN device or root.
//!
//! # Where this runs, and why the order is not negotiable
//!
//! Only after [`AmneziaConfig::strip_inbound`] has already returned `None` —
//! that is, after the datagram has failed to be AmneziaWG. The reverse order
//! answers our own clients: the invariant table in [`crate::noise::amnezia`]
//! shows that under `ip=dns` or `ip=sip`, at the S sizes an installer
//! generates, our cover traffic *is* a valid probe. A server that asked "is
//! this a probe?" first would reply to its own peers' pre-handshake junk
//! instead of handshaking with them, and would do so more often the better the
//! imitation became.
//!
//! # One protocol, not four
//!
//! A reply is built only when the detected protocol matches the configured
//! imitation protocol. Answering DNS *and* STUN *and* QUIC on one port would
//! describe a host that does not exist; the point is to look like the one
//! service the operator chose.
//!
//! [`AmneziaConfig::strip_inbound`]: crate::noise::amnezia::AmneziaConfig

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rand_core::RngCore;

use super::probe_budget::ProbeBudget;
use crate::noise::amnezia::{AmneziaConfig, AmneziaImitationProtocol};
use crate::noise::handshake::ObfuscationRanges;
use crate::noise::imitation::detect::{detect, Probe};
use crate::noise::imitation::{dns, stun};
use crate::noise::quic::version_negotiation;

/// A reply larger than this is refused outright.
///
/// Not a substitute for [`ProbeBudget`], which is the amplification control.
/// This is a backstop against a generator changing shape unnoticed: every
/// current reply is well under it (a STUN Binding Success with a long SOFTWARE
/// tops out near 200 bytes, a DNS SERVFAIL never exceeds its query, and a
/// Version Negotiation is under 60), so tripping it means something has changed
/// that should have been noticed.
const MAX_REPLY_LEN: usize = 1024;

/// The SOFTWARE value advertised in a STUN Binding Success.
///
/// Deliberately a generic stack rather than anything identifying: the value is
/// visible to whoever probed us, so a product-specific string would be its own
/// fingerprint.
const STUN_SOFTWARE: &str = "Chromium";

/// Rewrite an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as the IPv4 address
/// it denotes.
///
/// The v6 listening socket is dual-stack, so every IPv4 peer reaching it is
/// reported in this form, and it matters twice:
///
/// - The v6 arm of [`may_reply_to`] would let `::ffff:255.255.255.255` and
///   `::ffff:224.0.0.1` through, because neither `is_multicast` nor
///   `is_broadcast` looks inside the mapping. The hygiene rules have to see the
///   address family the datagram actually came from.
/// - A STUN XOR-MAPPED-ADDRESS would otherwise report family `0x02` with a
///   16-byte address to a client that reached us over IPv4. Real servers report
///   the family they saw, so the mapped form is its own fingerprint.
///
/// `Ipv6Addr::to_ipv4` also unwraps the deprecated IPv4-*compatible* form
/// (`::a.b.c.d`), which is not what arrives from a dual-stack socket; only the
/// mapped prefix is matched here.
fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.octets() {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), addr.port())
            }
            _ => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

/// Should we reply to this source address at all?
///
/// Independent of what the datagram contains. A source address is
/// attacker-chosen on a UDP socket, so these are the addresses a reply must
/// never be aimed at:
///
/// - **unspecified / loopback** — either bogus or a reply to ourselves;
/// - **multicast / broadcast** — one forged datagram becomes a reply hitting
///   every host on the segment, a multiplier no byte-based ceiling models;
/// - **link-local** — not routable, and reachable only by an on-segment host
///   that could have addressed us directly;
/// - **port 0** — not a real source;
/// - **our own listen port** — the reflection-loop case. Two servers pointed at
///   each other must not trade replies indefinitely, and this is the cheap
///   structural half of preventing it.
fn may_reply_to(from: SocketAddr, listen_port: u16) -> bool {
    if from.port() == 0 || from.port() == listen_port {
        return false;
    }
    match from.ip() {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            // `is_unicast_link_local` is unstable, so the fe80::/10 test is
            // written out rather than waiting for it.
            let is_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            !(v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() || is_link_local)
        }
    }
}

/// What ingress should do with a datagram that has not been authenticated.
pub(crate) enum Ingress<'a> {
    /// AmneziaWG framing recognised. This is the payload to verify, with any
    /// S-prefix already removed.
    Wireguard(&'a [u8]),
    /// Not ours. Send this back if it is `Some`, then drop the datagram.
    Foreign(Option<Vec<u8>>),
}

/// The whole per-datagram decision, in the one order that is correct.
///
/// This exists as a function rather than as two calls in the event handler so
/// the order is testable. It is not a stylistic preference: under `ip=dns` at
/// installer S sizes, a conforming AmneziaWG initiation *is* a well-formed DNS
/// query, and nothing in [`reply_to`] can tell it from a prober's. Ask "is this
/// a probe?" first and the server answers its own clients' handshakes with
/// SERVFAIL — and does so more reliably the better the imitation gets. The test
/// below asserts both halves: that the collision is real, and that this
/// function resolves it in favour of the tunnel.
///
/// `from` is an `Option` because that is what `socket2` yields; a datagram whose
/// source address will not convert cannot be replied to, but can still be
/// tunnel traffic.
pub(crate) fn classify<'a>(
    datagram: &'a [u8],
    amnezia: &AmneziaConfig,
    obf: ObfuscationRanges,
    from: Option<SocketAddr>,
    listen_port: u16,
    budget: Option<&ProbeBudget>,
    rng: &mut impl RngCore,
) -> Ingress<'a> {
    if let Some(packet) = amnezia.strip_inbound(obf, datagram) {
        return Ingress::Wireguard(packet);
    }
    let reply = budget.zip(from).and_then(|(budget, from)| {
        reply_to(
            datagram,
            from,
            listen_port,
            amnezia.imitation.protocol,
            budget,
            rng,
        )
    });
    Ingress::Foreign(reply)
}

/// Build the reply to an unauthenticated `request`, or `None` to stay silent.
///
/// `request` must already have failed AmneziaWG classification — see the module
/// docs for why that order is mandatory.
///
/// Charges [`ProbeBudget`] with the reply's real length, and only once a reply
/// has actually been built. Charging on the classifier's verdict instead would
/// bill for replies never sent: a QUIC detection does not imply a QUIC reply,
/// because `version_negotiation` refuses v1 and v2.
pub(crate) fn reply_to(
    request: &[u8],
    from: SocketAddr,
    listen_port: u16,
    imitation: AmneziaImitationProtocol,
    budget: &ProbeBudget,
    rng: &mut impl RngCore,
) -> Option<Vec<u8>> {
    // Before the hygiene rules, not after: a dual-stack socket reports IPv4
    // sources in the mapped form, and the v6 rules cannot see through it.
    let from = unmap(from);
    if !may_reply_to(from, listen_port) {
        return None;
    }

    // One protocol, not four: only answer as the service we are imitating.
    let probe = detect(request)?;
    if !probe.is(imitation) {
        return None;
    }

    let reply = match probe {
        Probe::Dns => dns::servfail(request)?,
        Probe::Stun => stun::binding_success(request, from, STUN_SOFTWARE)?,
        Probe::Quic => version_negotiation::version_negotiation(request, rng)?,
        // SIP has no responder. Its replies are stateful in a way a synthetic
        // cannot fake -- a real UAS absorbs INVITE retransmissions and answers
        // a CANCEL against the pending transaction -- so the honest behaviour
        // is silence rather than a plausible-looking lie.
        Probe::Sip => return None,
    };

    if reply.len() > MAX_REPLY_LEN {
        return None;
    }
    // Charged last, on the real length, and only for a reply we are about to
    // send. Charging earlier would let refused replies drain the ceiling.
    if !budget.try_consume(reply.len()) {
        return None;
    }
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    const PORT: u16 = 51820;

    fn budget() -> ProbeBudget {
        ProbeBudget::new(1 << 20)
    }

    fn dns_query() -> Vec<u8> {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        crate::noise::imitation::dns::generate("example.com", &mut rng).remove(0)
    }

    fn peer(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    /// The invariant the whole design rests on, in two halves.
    ///
    /// A conforming AmneziaWG initiation under `ip=dns`, at an S1 an installer
    /// actually generates, is *also* a well-formed DNS query — that is what the
    /// imitation is for. So:
    ///
    /// 1. [`reply_to`] on its own answers it. If this half ever stops holding,
    ///    the second half has gone vacuous and the test says so rather than
    ///    quietly passing.
    /// 2. [`classify`] nevertheless routes it to the tunnel, byte for byte.
    ///
    /// Reordering the two calls inside `classify` fails the second assertion.
    /// This is deliberately a unit test: the same thing observed through a live
    /// socket depends on a handshake completing, which is not something a test
    /// should have to wait on to learn about a pure ordering rule.
    #[test]
    fn a_conforming_initiation_is_tunnel_traffic_even_though_it_is_a_valid_dns_query() {
        use crate::noise::{HANDSHAKE_INIT, HANDSHAKE_INIT_SZ};

        let obf = ObfuscationRanges::default();
        // S1 = 150: large enough that the DNS filler builds a real query rather
        // than falling back to random padding, and in the range an installer
        // writes.
        let cfg = AmneziaConfig::new(150, 130, 110, 80).with_protocol_imitation(
            AmneziaImitationProtocol::Dns,
            Some("example.com".to_owned()),
        );

        let mut original = vec![0u8; HANDSHAKE_INIT_SZ];
        original[..4].copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
        for (i, byte) in original[4..].iter_mut().enumerate() {
            *byte = (i as u8) ^ 0x5a;
        }

        let mut buffer = vec![0u8; HANDSHAKE_INIT_SZ + 1280];
        buffer[..HANDSHAKE_INIT_SZ].copy_from_slice(&original);
        let mut junk_rng = ChaCha8Rng::seed_from_u64(0xA53);
        let padded = cfg
            .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, &mut junk_rng)
            .expect("S1 is large enough for the initiation")
            .to_vec();

        let client = peer("203.0.113.5:40000");
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        // Half one: the collision is real, so half two is not vacuous.
        assert!(
            reply_to(
                &padded,
                client,
                PORT,
                AmneziaImitationProtocol::Dns,
                &budget(),
                &mut rng
            )
            .is_some(),
            "our own padded initiation is supposed to be a valid DNS query; if it \
             is not, this test no longer guards anything"
        );

        // Half two: and yet it is tunnel traffic.
        match classify(
            &padded,
            &cfg,
            obf,
            Some(client),
            PORT,
            Some(&budget()),
            &mut rng,
        ) {
            Ingress::Wireguard(packet) => assert_eq!(
                packet,
                &original[..],
                "the initiation must come back exactly as it went in"
            ),
            Ingress::Foreign(_) => {
                panic!("a conforming AmneziaWG initiation was treated as foreign traffic")
            }
        }
    }

    /// A datagram that is neither AmneziaWG nor a probe is dropped in silence,
    /// which is what a bare WireGuard port already does.
    #[test]
    fn noise_is_dropped_without_a_reply() {
        let cfg = AmneziaConfig::default().with_protocol_imitation(
            AmneziaImitationProtocol::Dns,
            Some("example.com".to_owned()),
        );
        let mut rng = ChaCha8Rng::seed_from_u64(13);
        match classify(
            &[0x5a; 64],
            &cfg,
            ObfuscationRanges::default(),
            Some(peer("203.0.113.5:40000")),
            PORT,
            Some(&budget()),
            &mut rng,
        ) {
            Ingress::Foreign(reply) => assert!(reply.is_none(), "junk must not be answered"),
            Ingress::Wireguard(_) => panic!("64 bytes of junk parsed as AmneziaWG"),
        }
    }

    #[test]
    fn answers_a_dns_probe_when_imitating_dns() {
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let reply = reply_to(
            &dns_query(),
            peer("203.0.113.5:40000"),
            PORT,
            AmneziaImitationProtocol::Dns,
            &budget(),
            &mut rng,
        );
        assert!(reply.is_some(), "a DNS probe under ip=dns must be answered");
    }

    /// Answering every protocol on one port describes a host that does not
    /// exist. A DNS probe against a STUN-imitating server gets silence.
    #[test]
    fn does_not_answer_a_protocol_we_are_not_imitating() {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        for ip in [
            AmneziaImitationProtocol::None,
            AmneziaImitationProtocol::Stun,
            AmneziaImitationProtocol::Quic,
            AmneziaImitationProtocol::Sip,
        ] {
            assert!(
                reply_to(
                    &dns_query(),
                    peer("203.0.113.5:40000"),
                    PORT,
                    ip,
                    &budget(),
                    &mut rng
                )
                .is_none(),
                "{:?} must not answer a DNS probe",
                ip
            );
        }
    }

    /// A source address is attacker-chosen. Each of these turns one forged
    /// datagram into a reply somewhere it must never go.
    #[test]
    fn refuses_source_addresses_a_reply_must_never_target() {
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        let cases = [
            ("0.0.0.0:40000", "unspecified"),
            ("127.0.0.1:40000", "loopback"),
            ("224.0.0.1:40000", "multicast"),
            ("255.255.255.255:40000", "broadcast"),
            ("169.254.1.1:40000", "link-local"),
            ("203.0.113.5:0", "port 0"),
            ("[::]:40000", "v6 unspecified"),
            ("[::1]:40000", "v6 loopback"),
            ("[ff02::1]:40000", "v6 multicast"),
            ("[fe80::1]:40000", "v6 link-local"),
            // The dual-stack form. `Ipv6Addr::is_multicast` and friends do not
            // look inside the mapping, so these pass the v6 rules unless the
            // address is unmapped first -- and every IPv4 probe reaching the v6
            // socket arrives exactly like this.
            ("[::ffff:255.255.255.255]:40000", "v4-mapped broadcast"),
            ("[::ffff:224.0.0.1]:40000", "v4-mapped multicast"),
            ("[::ffff:127.0.0.1]:40000", "v4-mapped loopback"),
            ("[::ffff:169.254.1.1]:40000", "v4-mapped link-local"),
        ];
        for (addr, what) in cases {
            assert!(
                reply_to(
                    &dns_query(),
                    peer(addr),
                    PORT,
                    AmneziaImitationProtocol::Dns,
                    &budget(),
                    &mut rng
                )
                .is_none(),
                "{} must not be replied to",
                what
            );
        }

        // The reflection-loop case: a source claiming our own listen port.
        assert!(
            reply_to(
                &dns_query(),
                peer("203.0.113.5:51820"),
                PORT,
                AmneziaImitationProtocol::Dns,
                &budget(),
                &mut rng
            )
            .is_none(),
            "a source on our own listen port would trade replies forever"
        );
    }

    /// The mirror of the rejection list: a legitimate IPv4 source arriving via
    /// the dual-stack socket is still answered, and answered *identically* to
    /// the same source arriving over IPv4. Byte equality is the assertion
    /// because the difference would otherwise be inside the STUN
    /// XOR-MAPPED-ADDRESS, reporting an IPv6 family to an IPv4 client.
    #[test]
    fn a_v4_mapped_source_gets_the_same_reply_as_the_plain_v4_one() {
        let client = peer("203.0.113.5:40000");
        let mapped = peer("[::ffff:203.0.113.5]:40000");

        let mut request = vec![0u8; 20];
        request[0..2].copy_from_slice(&[0x00, 0x01]);
        request[4..8].copy_from_slice(&stun::MAGIC_COOKIE);
        for (i, b) in request[8..20].iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let over_v4 = reply_to(
            &request,
            client,
            PORT,
            AmneziaImitationProtocol::Stun,
            &budget(),
            &mut rng,
        );
        let over_v6 = reply_to(
            &request,
            mapped,
            PORT,
            AmneziaImitationProtocol::Stun,
            &budget(),
            &mut rng,
        );
        assert!(over_v4.is_some(), "a plain v4 source is answered");
        assert_eq!(
            over_v4, over_v6,
            "the mapped form must not change the reply the client sees"
        );
    }

    /// The budget is charged on the reply that is actually produced, so a
    /// detection that yields no reply must leave the allowance *untouched* —
    /// not merely mostly untouched.
    ///
    /// The allowance is exactly one reply, so a premature charge of even a
    /// single byte on the refused path is enough to starve the legitimate reply
    /// that follows. Sized generously, this test passes against a mutant that
    /// charges on the classifier's verdict.
    #[test]
    fn a_refused_reply_does_not_spend_one_byte_of_the_budget() {
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let query = dns_query();
        let reply_len = dns::servfail(&query).expect("answerable").len();
        let b = ProbeBudget::new(reply_len as u32);

        // Wrong protocol: detected, never built, must not be charged.
        for _ in 0..100 {
            assert!(reply_to(
                &query,
                peer("203.0.113.5:40000"),
                PORT,
                AmneziaImitationProtocol::Stun,
                &b,
                &mut rng
            )
            .is_none());
        }
        // The allowance is intact to the byte, so the one reply it covers fits.
        assert!(
            reply_to(
                &query,
                peer("203.0.113.5:40000"),
                PORT,
                AmneziaImitationProtocol::Dns,
                &b,
                &mut rng
            )
            .is_some(),
            "100 refused replies must not have taken a byte off the ceiling"
        );
    }

    /// SIP is detected but never answered: a synthetic cannot hold the
    /// transaction state a real UAS has, so silence is the honest behaviour.
    #[test]
    fn sip_is_detected_but_not_answered() {
        let mut rng = ChaCha8Rng::seed_from_u64(6);
        let invite = b"INVITE sip:a@b SIP/2.0\r\n\r\n";
        assert_eq!(detect(invite), Some(Probe::Sip), "detected");
        assert!(
            reply_to(
                invite,
                peer("203.0.113.5:40000"),
                PORT,
                AmneziaImitationProtocol::Sip,
                &budget(),
                &mut rng
            )
            .is_none(),
            "but not answered"
        );
    }

    /// Once the ceiling is spent, replies stop. This is the property that
    /// bounds what answering unauthenticated traffic can cost, so it is
    /// asserted as an exact count rather than as "eventually stops": a charge of
    /// the wrong size, or no charge at all, changes the number.
    ///
    /// The allowance is sized from the reply this build actually produces, so
    /// the test does not silently loosen if a generator changes shape.
    #[test]
    fn the_ceiling_admits_exactly_what_it_allows_and_no_more() {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let query = dns_query();
        let reply_len = dns::servfail(&query).expect("answerable").len();

        // Room for four replies a second. Refill over the microseconds this
        // loop takes is a fraction of a byte, so a fifth cannot slip through.
        let b = ProbeBudget::new(4 * reply_len as u32);
        let admitted = (0..100)
            .filter(|_| {
                reply_to(
                    &query,
                    peer("203.0.113.5:40000"),
                    PORT,
                    AmneziaImitationProtocol::Dns,
                    &b,
                    &mut rng,
                )
                .is_some()
            })
            .count();

        assert_eq!(
            admitted, 4,
            "an allowance of four {}-byte replies must admit four, not {}",
            reply_len, admitted
        );
    }

    /// Our own pre-handshake DNS cover traffic **is** answered here.
    ///
    /// Not a defect — a SERVFAIL to a client's imitation burst is harmless, and
    /// arguably more realistic than silence. It is pinned because it shows that
    /// there is no "is this ours?" test at this layer and none is possible: the
    /// burst is a well-formed DNS query by construction, indistinguishable from
    /// a prober's. The only thing standing between a *real handshake* and a
    /// SERVFAIL is that the caller runs `strip_inbound` first, which is why the
    /// module doc calls that order mandatory rather than preferred.
    #[test]
    fn our_own_dns_cover_traffic_is_answered_because_nothing_here_can_tell() {
        let mut rng = ChaCha8Rng::seed_from_u64(8);
        let mut gen_rng = ChaCha8Rng::seed_from_u64(9);
        for pkt in crate::noise::imitation::dns::generate("example.com", &mut gen_rng) {
            assert!(
                reply_to(
                    &pkt,
                    peer("203.0.113.5:40000"),
                    PORT,
                    AmneziaImitationProtocol::Dns,
                    &budget(),
                    &mut rng
                )
                .is_some(),
                "nothing at this layer distinguishes our own burst from a probe"
            );
        }
    }

    /// [`MAX_REPLY_LEN`] is a backstop that no current generator can reach, and
    /// this asserts the margin rather than leaving that claim in a comment. If a
    /// generator ever grows past it the reply would be silently dropped, so the
    /// failure should arrive here, not in production.
    #[test]
    fn every_generator_stays_well_under_the_backstop() {
        let mut rng = ChaCha8Rng::seed_from_u64(10);
        let client = peer("203.0.113.5:40000");

        // DNS: header plus the echoed question, bounded by a 255-byte QNAME.
        let dns = dns::servfail(&dns_query()).expect("a generated query is answerable");

        // STUN: the largest reply this module can build -- a maximum-length
        // SOFTWARE value, which `binding_success` caps at 127 bytes.
        let long_software = "x".repeat(127);
        let mut request = vec![0u8; 20];
        request[0..2].copy_from_slice(&[0x00, 0x01]); // Binding Request
        request[4..8].copy_from_slice(&stun::MAGIC_COOKIE);
        for (i, b) in request[8..20].iter_mut().enumerate() {
            *b = i as u8;
        }
        let stun_reply = stun::binding_success(&request, client, &long_software)
            .expect("a minimal Binding Request is answerable");

        for (what, len) in [("DNS", dns.len()), ("STUN", stun_reply.len())] {
            assert!(
                len * 2 < MAX_REPLY_LEN,
                "{} reply is {} bytes, no longer comfortably under the {}-byte backstop",
                what,
                len,
                MAX_REPLY_LEN
            );
        }

        // QUIC: a Version Negotiation is a header plus one 4-byte version per
        // advertised entry, so it is the smallest of the three. Built through
        // the real path so the bound covers whatever the version list becomes.
        let mut initial = vec![0u8; 1200];
        initial[0] = 0xC0;
        initial[1..5].copy_from_slice(&0xff00_001du32.to_be_bytes()); // a draft version
        let vn = version_negotiation::version_negotiation(&initial, &mut rng)
            .expect("a draft-version Initial is answerable");
        assert!(
            vn.len() * 2 < MAX_REPLY_LEN,
            "QUIC reply is {} bytes, no longer comfortably under the {}-byte backstop",
            vn.len(),
            MAX_REPLY_LEN
        );
    }
}
