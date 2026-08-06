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
//! generates, our cover traffic *is* a valid probe.
//!
//! Under `ip=dns` that is immediately fatal — a probe-first server SERVFAILs
//! its own peers' handshake initiations. Under `ip=sip` it would be, except
//! that [`reply_to`] has no SIP responder, so the datagram is merely dropped
//! rather than answered; a probe-first server would still lose the handshake,
//! just more quietly. Either way the failure gets *more* reliable the better
//! the imitation becomes, which is why the order lives in one tested function
//! and not in the event loop.
//!
//! # One protocol, not four
//!
//! A reply is built only when the detected protocol matches the configured
//! imitation protocol. Answering DNS *and* STUN *and* QUIC on one port would
//! describe a host that does not exist; the point is to look like the one
//! service the operator chose.
//!
//! [`AmneziaConfig::strip_inbound`]: crate::noise::amnezia::AmneziaConfig

use std::net::SocketAddr;

use rand_core::RngCore;

use super::probe_budget::ProbeBudget;
use super::reply_policy::reply_target;
use crate::noise::amnezia::{AmneziaConfig, AmneziaImitationProtocol};
use crate::noise::handshake::ObfuscationRanges;
use crate::noise::imitation::detect::{detect, Probe};
use crate::noise::imitation::{dns, stun};
use crate::noise::quic::version_negotiation;

/// A reply larger than this is refused outright.
///
/// Not the amplification control — [`ProbeBudget`] is that, and each generator
/// carries its own bound, asserted where it is derived rather than restated
/// here as a number that would go stale: a DNS SERVFAIL is never larger than
/// its query, a STUN Binding Success is capped by `stun::MAX_SOFTWARE_LEN`, and
/// a Version Negotiation by [`version_negotiation::MAX_LEN`] (525 bytes, and
/// pinned there against `MIN_INITIAL_DATAGRAM`).
///
/// This is the backstop for a generator changing shape unnoticed. It must stay
/// **below** `MIN_INITIAL_DATAGRAM` (1200): the QUIC responder only answers
/// datagrams of at least that size, so a ceiling under it is what keeps a reply
/// from ever exceeding the smallest request able to elicit one. Raising this to
/// buy a test some margin would give that away.
const MAX_REPLY_LEN: usize = 1024;

// Both relationships are between constants, so they are enforced by the
// compiler rather than by a test that someone could delete. The second is the
// one that carries the security meaning: a reply can never be larger than the
// smallest datagram able to elicit one.
const _: () = assert!(version_negotiation::MAX_LEN < MAX_REPLY_LEN);
const _: () = assert!(MAX_REPLY_LEN < version_negotiation::MIN_INITIAL_DATAGRAM);

/// Device-scoped state for answering probes.
///
/// Exists so the reply path takes one parameter instead of three, and so the
/// SOFTWARE value below is read once per device rather than per reply.
pub(crate) struct ProbeResponder {
    budget: ProbeBudget,
    /// The SOFTWARE advertised in a STUN Binding Success.
    ///
    /// Drawn from `stun::SOFTWARE_POOL` — the same curated list the outbound
    /// Binding Requests use — rather than restated here. A second literal was
    /// both a duplicate and a mismatch: a device configured `ip=stun` would send
    /// checks announcing one of five stacks and answer as a hardcoded sixth.
    ///
    /// Chosen **once per process**, not per reply and not per device. Under
    /// `ip=stun` this port is an ICE agent, not a STUN server — ICE peers send
    /// Binding Requests to each other and answer with Binding Success — and a
    /// single agent has one SOFTWARE. Re-rolling it per reply would be the
    /// anomaly.
    ///
    /// `stun::host_software()` rather than a draw of this responder's own, so
    /// the outbound Binding Requests announce the same stack this answers with.
    /// A per-device draw was still half the fingerprint: the requests came from
    /// `stun::generate`, which re-rolled per burst, so one host presented
    /// several ICE stacks on the one port the connected per-peer sockets share.
    software: &'static str,
}

impl ProbeResponder {
    pub(crate) fn new(bytes_per_sec: u32) -> Self {
        Self {
            budget: ProbeBudget::new(bytes_per_sec),
            software: stun::host_software(),
        }
    }
}

/// What ingress should do with a datagram that has not been authenticated.
///
/// Three flat variants rather than `Foreign(Option<Vec<u8>>)`: the two-level
/// form made the caller destructure twice, and let a test assert on the payload
/// (`Foreign(reply)` then `reply.is_none()`) where it should assert on the
/// outcome. `Drop` is a distinct variant, so "answered" and "stayed silent"
/// cannot be confused by a test that only looks one level deep.
pub(crate) enum Ingress<'a> {
    /// AmneziaWG framing recognised. This is the payload to verify, with any
    /// S-prefix already removed.
    Wireguard(&'a [u8]),
    /// Not ours, and worth answering. Send this, then drop the datagram.
    Reply(Vec<u8>),
    /// Not ours, and not worth answering. Drop it in silence — which is what a
    /// bare WireGuard port does with everything.
    Drop,
}

/// The whole per-datagram decision, in the one order that is correct.
///
/// A function rather than two calls in the event handler so that the order is
/// testable — see the module docs for why it is mandatory, and
/// [`tests::a_conforming_initiation_is_tunnel_traffic_even_though_it_is_a_valid_dns_query`]
/// for the test that pins it.
///
/// `responder` is `None` when probe replies are switched off, which is the
/// default and the only state a vanilla WireGuard interface has.
pub(crate) fn classify<'a>(
    datagram: &'a [u8],
    amnezia: &AmneziaConfig,
    obf: ObfuscationRanges,
    from: SocketAddr,
    responder: Option<&ProbeResponder>,
    rng: &mut impl RngCore,
) -> Ingress<'a> {
    if let Some(packet) = amnezia.strip_inbound(obf, datagram) {
        return Ingress::Wireguard(packet);
    }
    match responder.and_then(|r| reply_to(datagram, from, amnezia.imitation.protocol, r, rng)) {
        Some(reply) => Ingress::Reply(reply),
        None => Ingress::Drop,
    }
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
/// Private, not `pub(crate)`: [`classify`] is the only door. This function
/// deliberately does *not* check whether the datagram was AmneziaWG first, so a
/// crate-visible version would advertise the one entry point that bypasses the
/// invariant the module exists to enforce.
fn reply_to(
    request: &[u8],
    from: SocketAddr,
    imitation: AmneziaImitationProtocol,
    responder: &ProbeResponder,
    rng: &mut impl RngCore,
) -> Option<Vec<u8>> {
    // Cheapest test first, and the one that short-circuits the common case: a
    // vanilla interface, or one imitating nothing, never runs the classifier at
    // all. `detect` walks a DNS QNAME and eleven SIP prefixes, and it would run
    // on every datagram that fails `strip_inbound` — for a verdict that
    // `probe.is(imitation)` was always going to discard.
    if imitation == AmneziaImitationProtocol::None {
        return None;
    }

    // The shared source-address rule, which the cookie-reply path in `super`
    // also goes through. It hands back the *unmapped* address, which is what
    // `binding_success` must put in XOR-MAPPED-ADDRESS; see `reply_target` for
    // why the check and the unmapping are one call rather than two.
    let from = reply_target(from)?;

    // One protocol, not four: only answer as the service we are imitating.
    let probe = detect(request)?;
    if !probe.is(imitation) {
        return None;
    }

    let reply = match probe {
        Probe::Dns => dns::servfail(request)?,
        Probe::Stun => stun::binding_success(request, from, responder.software)?,
        Probe::Quic => version_negotiation::version_negotiation(request, rng)?,
        // SIP has no responder. Its replies are stateful in a way a synthetic
        // cannot fake -- a real UAS absorbs INVITE retransmissions and answers
        // a CANCEL against the pending transaction -- so the honest behaviour
        // is silence rather than a plausible-looking lie.
        Probe::Sip => return None,
    };

    if reply.len() > MAX_REPLY_LEN {
        // Logged, not silent. Every generator is bounded well under this and
        // there is a test asserting so, which means reaching here is a change
        // nobody noticed -- and the symptom would otherwise be a port that goes
        // quiet for one protocol with nothing to explain it.
        tracing::debug!(
            message = "probe reply exceeds the size backstop; dropping",
            len = reply.len(),
            max = MAX_REPLY_LEN
        );
        return None;
    }
    // Charged last, on the real length, and only for a reply we are about to
    // send. Charging earlier would let refused replies drain the ceiling.
    if !responder.budget.try_consume(reply.len()) {
        return None;
    }
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::amnezia::conforming_initiation;
    use crate::noise::quic::version_negotiation::{MAX_LEN as VN_MAX_LEN, MIN_INITIAL_DATAGRAM};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    /// Large enough that no test hits the ceiling by accident; the tests that
    /// mean to exercise it build their own.
    fn responder() -> ProbeResponder {
        ProbeResponder::new(1 << 20)
    }

    fn cfg(protocol: AmneziaImitationProtocol) -> AmneziaConfig {
        AmneziaConfig::default().with_protocol_imitation(protocol, Some("example.com".to_owned()))
    }

    fn peer(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    fn dns_query() -> Vec<u8> {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        crate::noise::imitation::dns::generate("example.com", &mut rng).remove(0)
    }

    /// A minimal, well-framed Binding Request: header, magic cookie,
    /// transaction id, no attributes.
    fn stun_request() -> Vec<u8> {
        let mut m = vec![0u8; 20];
        m[0..2].copy_from_slice(&[0x00, 0x01]);
        m[4..8].copy_from_slice(&stun::MAGIC_COOKIE);
        for (i, b) in m[8..20].iter_mut().enumerate() {
            *b = i as u8;
        }
        m
    }

    /// A long-header Initial offering `version`, with `cid_len`-byte connection
    /// IDs, padded to the RFC 9000 section 14.1 floor.
    fn quic_initial(version: u32, cid_len: usize) -> Vec<u8> {
        let mut p = vec![0xC3];
        p.extend_from_slice(&version.to_be_bytes());
        p.push(cid_len as u8);
        p.extend(std::iter::repeat_n(0xAB, cid_len));
        p.push(cid_len as u8);
        p.extend(std::iter::repeat_n(0xCD, cid_len));
        p.resize(MIN_INITIAL_DATAGRAM.max(p.len()), 0);
        p
    }

    fn reply(request: &[u8], from: &str, protocol: AmneziaImitationProtocol) -> Option<Vec<u8>> {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        reply_to(request, peer(from), protocol, &responder(), &mut rng)
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
    /// Deliberately a unit test: the same thing observed through a live socket
    /// depends on a handshake completing, which is not something a test should
    /// have to wait on to learn about a pure ordering rule.
    #[test]
    fn a_conforming_initiation_is_tunnel_traffic_even_though_it_is_a_valid_dns_query() {
        let obf = ObfuscationRanges::default();
        // S1 = 150: large enough that the DNS filler builds a real query rather
        // than falling back to random padding, and in the range an installer
        // writes.
        let config = AmneziaConfig::new(150, 130, 110, 80).with_protocol_imitation(
            AmneziaImitationProtocol::Dns,
            Some("example.com".to_owned()),
        );
        let (original, padded) =
            conforming_initiation(&config, obf, &mut ChaCha8Rng::seed_from_u64(0xA53));

        // Half one: the collision is real, so half two is not vacuous.
        assert!(
            reply(&padded, "203.0.113.5:40000", AmneziaImitationProtocol::Dns).is_some(),
            "our own padded initiation is supposed to be a valid DNS query; if it \
             is not, this test no longer guards anything"
        );

        // Half two: and yet it is tunnel traffic.
        let mut rng = ChaCha8Rng::seed_from_u64(12);
        match classify(
            &padded,
            &config,
            obf,
            peer("203.0.113.5:40000"),
            Some(&responder()),
            &mut rng,
        ) {
            Ingress::Wireguard(packet) => assert_eq!(
                packet,
                &original[..],
                "the initiation must come back exactly as it went in"
            ),
            Ingress::Reply(_) => panic!("a conforming initiation was answered as a probe"),
            Ingress::Drop => panic!("a conforming initiation was dropped"),
        }
    }

    /// A datagram that is neither AmneziaWG nor a probe is dropped in silence,
    /// which is what a bare WireGuard port already does.
    #[test]
    fn noise_is_dropped_without_a_reply() {
        let mut rng = ChaCha8Rng::seed_from_u64(13);
        match classify(
            &[0x5a; 64],
            &cfg(AmneziaImitationProtocol::Dns),
            ObfuscationRanges::default(),
            peer("203.0.113.5:40000"),
            Some(&responder()),
            &mut rng,
        ) {
            Ingress::Drop => {}
            Ingress::Reply(r) => panic!("64 bytes of junk drew a {}-byte reply", r.len()),
            Ingress::Wireguard(_) => panic!("64 bytes of junk parsed as AmneziaWG"),
        }
    }

    /// With no responder configured — the default, and every vanilla WireGuard
    /// interface — a probe is dropped rather than answered.
    #[test]
    fn a_device_without_a_responder_answers_nothing() {
        let mut rng = ChaCha8Rng::seed_from_u64(14);
        match classify(
            &dns_query(),
            &cfg(AmneziaImitationProtocol::Dns),
            ObfuscationRanges::default(),
            peer("203.0.113.5:40000"),
            None,
            &mut rng,
        ) {
            Ingress::Drop => {}
            Ingress::Reply(_) => panic!("replies are off; nothing may be sent"),
            Ingress::Wireguard(_) => panic!("a DNS query parsed as AmneziaWG"),
        }
    }

    #[test]
    fn answers_a_dns_probe_when_imitating_dns() {
        assert!(
            reply(
                &dns_query(),
                "203.0.113.5:40000",
                AmneziaImitationProtocol::Dns
            )
            .is_some(),
            "a DNS probe under ip=dns must be answered"
        );
    }

    /// Answering every protocol on one port describes a host that does not
    /// exist. A DNS probe against a STUN-imitating server gets silence.
    #[test]
    fn does_not_answer_a_protocol_we_are_not_imitating() {
        for protocol in [
            AmneziaImitationProtocol::None,
            AmneziaImitationProtocol::Stun,
            AmneziaImitationProtocol::Quic,
            AmneziaImitationProtocol::Sip,
        ] {
            assert!(
                reply(&dns_query(), "203.0.113.5:40000", protocol).is_none(),
                "{:?} must not answer a DNS probe",
                protocol
            );
        }
    }

    /// This module actually consults the shared source-address rule.
    ///
    /// The rule itself, and the full table of addresses a reply must never be
    /// aimed at, is tested in [`super::super::reply_policy`] — including the
    /// v4-mapped forms, which is the part a caller could plausibly get wrong.
    /// What is asserted here is only the wiring: `reply_to` calls
    /// `reply_target`, so a probe that would otherwise be answered is not.
    /// Both rows are answerable — `answers_a_dns_probe_when_imitating_dns`
    /// covers the same query from an ordinary source — so a `None` here is the
    /// address rule and nothing else.
    #[test]
    fn the_shared_source_address_rule_is_applied() {
        for addr in ["255.255.255.255:40000", "[::ffff:224.0.0.1]:40000"] {
            assert!(
                reply(&dns_query(), addr, AmneziaImitationProtocol::Dns).is_none(),
                "{} must not be replied to",
                addr
            );
        }
    }

    /// The source port is not part of the decision, and specifically a source on
    /// our own listen port is answered like any other.
    ///
    /// The reverse — silence for that one port — was a one-packet discriminator:
    /// a prober knows the port it is dialling, so it can send the same probe
    /// twice and read the difference. No real server behaves that way. See
    /// `reply_policy::may_reply_to`, and
    /// [`no_generated_reply_can_itself_be_detected_as_a_probe`] for the property
    /// that makes the check unnecessary.
    #[test]
    fn the_source_port_does_not_change_the_answer() {
        let q = dns_query();
        let from_ephemeral = reply(&q, "203.0.113.5:40000", AmneziaImitationProtocol::Dns);
        let from_listen_port = reply(&q, "203.0.113.5:51820", AmneziaImitationProtocol::Dns);
        assert!(from_ephemeral.is_some(), "the ordinary case is answered");
        assert_eq!(
            from_ephemeral, from_listen_port,
            "a probe from our own listen port must get the same reply as any other"
        );
    }

    /// The property that makes the reflection loop impossible, and therefore
    /// makes a source-port check unnecessary: nothing this crate emits in reply
    /// is itself classifiable as a probe.
    ///
    /// Stronger than the check it replaces, which only covered two servers that
    /// happened to share a listen port. This covers any pair, on any ports.
    #[test]
    fn no_generated_reply_can_itself_be_detected_as_a_probe() {
        let mut rng = ChaCha8Rng::seed_from_u64(21);
        let client = peer("203.0.113.5:40000");

        let servfail = dns::servfail(&dns_query()).expect("a generated query is answerable");
        assert_eq!(
            detect(&servfail),
            None,
            "a SERVFAIL must not read as a probe"
        );

        let success = stun::binding_success(&stun_request(), client, "Chromium")
            .expect("a minimal Binding Request is answerable");
        assert_eq!(
            detect(&success),
            None,
            "a Binding Success must not read as a probe"
        );

        // Both answerable QUIC version classes, and both connection-ID extremes.
        for version in [0xff00_001du32, 0x0a0a_0a0au32] {
            for cid_len in [0usize, 255] {
                let vn = version_negotiation::version_negotiation(
                    &quic_initial(version, cid_len),
                    &mut rng,
                )
                .unwrap_or_else(|| panic!("version {:#x} must be answered", version));
                assert_eq!(
                    detect(&vn),
                    None,
                    "a Version Negotiation ({:#x}, {}-byte CIDs) must not read as a probe",
                    version,
                    cid_len
                );
            }
        }
    }

    /// The mirror of the rejection list: a legitimate IPv4 source arriving via
    /// the dual-stack socket is still answered, and answered *identically* to
    /// the same source arriving over IPv4. Byte equality is the assertion
    /// because the difference would otherwise be inside the STUN
    /// XOR-MAPPED-ADDRESS, reporting an IPv6 family to an IPv4 client.
    #[test]
    fn a_v4_mapped_source_gets_the_same_reply_as_the_plain_v4_one() {
        let request = stun_request();
        let over_v4 = reply(
            &request,
            "203.0.113.5:40000",
            AmneziaImitationProtocol::Stun,
        );
        let over_v6 = reply(
            &request,
            "[::ffff:203.0.113.5]:40000",
            AmneziaImitationProtocol::Stun,
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
    /// that follows. Sized generously, this passes against a mutant that charges
    /// on the classifier's verdict.
    #[test]
    fn a_refused_reply_does_not_spend_one_byte_of_the_budget() {
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let query = dns_query();
        let reply_len = dns::servfail(&query).expect("answerable").len();
        let r = ProbeResponder::new(reply_len as u32);
        let from = peer("203.0.113.5:40000");

        // Wrong protocol: detected, never built, must not be charged.
        for _ in 0..100 {
            assert!(reply_to(&query, from, AmneziaImitationProtocol::Stun, &r, &mut rng).is_none());
        }
        assert!(
            reply_to(&query, from, AmneziaImitationProtocol::Dns, &r, &mut rng).is_some(),
            "100 refused replies must not have taken a byte off the ceiling"
        );
    }

    /// SIP is detected but never answered: a synthetic cannot hold the
    /// transaction state a real UAS has, so silence is the honest behaviour.
    #[test]
    fn sip_is_detected_but_not_answered() {
        let invite = b"INVITE sip:a@b SIP/2.0\r\n\r\n";
        assert_eq!(detect(invite), Some(Probe::Sip), "detected");
        assert!(
            reply(invite, "203.0.113.5:40000", AmneziaImitationProtocol::Sip).is_none(),
            "but not answered"
        );
    }

    /// Once the ceiling is spent, replies stop. Asserted as an exact count
    /// rather than "eventually stops": a charge of the wrong size, or no charge
    /// at all, changes the number.
    #[test]
    fn the_ceiling_admits_exactly_what_it_allows_and_no_more() {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let query = dns_query();
        let reply_len = dns::servfail(&query).expect("answerable").len();
        let from = peer("203.0.113.5:40000");

        // Room for four replies a second. Refill over the microseconds this
        // loop takes is a fraction of a byte, so a fifth cannot slip through.
        let r = ProbeResponder::new(4 * reply_len as u32);
        let admitted = (0..100)
            .filter(|_| {
                reply_to(&query, from, AmneziaImitationProtocol::Dns, &r, &mut rng).is_some()
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
        let mut gen_rng = ChaCha8Rng::seed_from_u64(9);
        for pkt in crate::noise::imitation::dns::generate("example.com", &mut gen_rng) {
            assert!(
                reply(&pkt, "203.0.113.5:40000", AmneziaImitationProtocol::Dns).is_some(),
                "nothing at this layer distinguishes our own burst from a probe"
            );
        }
    }

    /// Every generator's **worst case** stays under [`MAX_REPLY_LEN`], asserted
    /// against real measurements rather than against a made-up margin.
    ///
    /// The earlier version fed zero-length QUIC connection IDs and asserted
    /// `len * 2 < MAX_REPLY_LEN`. Both were wrong. The zero-length input
    /// measured a 15-byte reply when 525 is reachable, and the `* 2` was an
    /// invented factor — against the real worst case it fails (1050 > 1024)
    /// while nothing is actually broken, which would have invited someone to
    /// raise `MAX_REPLY_LEN` past `MIN_INITIAL_DATAGRAM` and give away the
    /// property that makes this port an attenuator.
    #[test]
    fn every_generator_stays_under_the_backstop_at_its_worst_case() {
        let mut rng = ChaCha8Rng::seed_from_u64(10);

        // DNS: header plus the echoed question, and never larger than the query.
        let query = dns_query();
        let dns_max = dns::servfail(&query).expect("answerable").len();
        assert!(
            dns_max <= query.len(),
            "a SERVFAIL must never exceed its query ({} vs {})",
            dns_max,
            query.len()
        );

        // STUN: the longest SOFTWARE `binding_success` accepts, to an IPv6
        // client (the larger XOR-MAPPED-ADDRESS).
        let long_software = "x".repeat(127);
        let stun_max =
            stun::binding_success(&stun_request(), peer("[2001:db8::1]:40000"), &long_software)
                .expect("a minimal Binding Request is answerable")
                .len();
        assert!(
            stun_max < MAX_REPLY_LEN,
            "the largest STUN reply is {} bytes, over the {}-byte backstop",
            stun_max,
            MAX_REPLY_LEN
        );

        // QUIC: 255-byte connection IDs, which is what the responder actually
        // permits — the 20-byte RFC 9000 cap is not applied to the versions it
        // answers. The bound is derived and pinned in `version_negotiation`;
        // here we only confirm the worst case is reached and clears the
        // backstop.
        let vn =
            version_negotiation::version_negotiation(&quic_initial(0xff00_001d, 255), &mut rng)
                .expect("a draft-version Initial is answerable");
        assert_eq!(vn.len(), VN_MAX_LEN, "the worst case really is VN_MAX_LEN");
        assert!(dns_max < MAX_REPLY_LEN, "DNS reply over the backstop");

        // `VN_MAX_LEN < MAX_REPLY_LEN` and `MAX_REPLY_LEN < MIN_INITIAL_DATAGRAM`
        // are relationships between constants, so they are `const _: () =
        // assert!(..)` at the top of this module and fail the *build*. That is
        // what stops anyone raising MAX_REPLY_LEN to make something pass; a
        // runtime assertion here would only be a lint about a constant.
    }

    /// The STUN SOFTWARE is pinned for the process and comes from the shared
    /// pool, so no two responders — and no responder and request generator —
    /// announce different stacks.
    ///
    /// The "varies across hosts" half cannot be asserted here: within one test
    /// binary there is one process and therefore one value, which is the property
    /// under test. That half is
    /// [`stun::tests::the_software_pool_is_not_effectively_a_constant`], on the
    /// draw that seeds the pin.
    #[test]
    fn the_stun_software_is_pinned_and_from_the_shared_pool() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            seen.insert(ProbeResponder::new(1 << 20).software);
        }
        assert_eq!(
            seen.len(),
            1,
            "every responder in a process must announce one stack, saw {:?}",
            seen
        );

        let mut pool = std::collections::HashSet::new();
        for seed in 0..512u64 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            pool.insert(stun::pick_software(&mut rng));
        }
        assert!(
            seen.is_subset(&pool),
            "responder announced {:?}, which the request generator never sends",
            seen.difference(&pool).collect::<Vec<_>>()
        );
    }
}
