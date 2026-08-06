// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! May we send bytes to this unauthenticated source, and how many of them?
//!
//! Two places on the ingress path write to an address nobody has proved
//! anything about, and before this module they answered that question
//! differently:
//!
//! - [`super::probe_reply`], which answers DNS/STUN/QUIC probes. It applies the
//!   rules below, plus an aggregate byte ceiling ([`super::probe_budget`]).
//! - the cookie-reply arm of `register_udp_handler`, which is stock WireGuard's
//!   own flood defence and predates every line of the probe work. It applied
//!   nothing: any source address, any size.
//!
//! The second was the older and the more exposed of the two. `mac1` is keyed on
//! the server's *public* key, which is in every client configuration, so an
//! attacker who has ever seen one can reach the cookie path with a forged
//! source address and no secret at all. The probe responder's module docs argue
//! that a reply to a spoofable source is "a multiplier no byte-based ceiling
//! models" — and that was true ten lines above a call site where the multiplier
//! ran unguarded.
//!
//! So the address rules live here, with one door ([`reply_target`]) that both
//! callers go through. The size rules do **not** unify, and [`cookie_verdict`]
//! explains why: the two paths are bounded by different things because they
//! fail in different ways.

use std::net::{IpAddr, SocketAddr};

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
/// `Ipv6Addr::to_ipv4_mapped`, not `to_ipv4`: the latter also unwraps the
/// deprecated IPv4-*compatible* form (`::a.b.c.d`), which a dual-stack socket
/// never produces and which should keep failing the v6 rules below.
///
/// Private, and reachable only through [`reply_target`]. Exported on its own it
/// would be one half of a pair a caller has to remember to use in the right
/// order — which is exactly the bug it exists to prevent.
fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
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
/// - **`0.0.0.0/8` and `240.0.0.0/4`** — "this network" and reserved space; a
///   reply to either dies at the first hop, so it is budget spent on nothing;
/// - **port 0** — not a real source.
///
/// None of these is an address a real peer can hold, which is what makes the
/// rule safe to apply to the cookie path as well: a cookie reply suppressed
/// here was never going to reach anyone who could use it.
///
/// What it does **not** catch is a directed broadcast (`192.168.1.255`), which
/// needs the local prefix to recognise. Linux refuses `sendto` to a
/// locally-recognised broadcast address without `SO_BROADCAST`, which this
/// socket does not set, and RFC 2644 has routers drop remote ones — so the
/// defence there is the kernel's, not this function's. Said plainly because the
/// list above otherwise reads as exhaustive.
///
/// There is deliberately **no check on the source port matching our own listen
/// port**. It was here to stop two imitating servers trading replies, but that
/// loop cannot form: no reply this crate generates is classifiable as a probe,
/// so a reply arriving at a second server is simply dropped. That is asserted
/// by `probe_reply`'s `no_generated_reply_can_itself_be_detected_as_a_probe`,
/// which holds for servers on *different* ports too — a source-port test never
/// did. A cookie reply cannot loop either, for a duller reason: it carries a
/// receiver index no second server has issued, so peer lookup drops it.
///
/// What the check did buy was a fingerprint. A prober knows our listen port; it
/// is the port it is dialling. Sending one probe from source port 51820 and one
/// from 40000 got silence and a SERVFAIL — a one-packet discriminator that no
/// real DNS, STUN or QUIC server exhibits, in a module whose entire purpose is
/// not to be discriminable.
fn may_reply_to(from: SocketAddr) -> bool {
    if from.port() == 0 {
        return false;
    }
    match from.ip() {
        IpAddr::V4(v4) => {
            // `is_unspecified` is only 0.0.0.0 exactly, and `is_broadcast` only
            // 255.255.255.255, so 0.0.0.0/8 ("this network") and 240.0.0.0/4
            // (reserved) are spelled out. Neither can be a real source; a reply
            // to one is budget spent on a datagram that dies at the first hop.
            let this_network = v4.octets()[0] == 0;
            let reserved = v4.octets()[0] >= 240;
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || this_network
                || reserved)
        }
        IpAddr::V6(v6) => {
            // `is_unicast_link_local` is unstable, so the fe80::/10 test is
            // written out rather than waiting for it.
            let is_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            !(v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() || is_link_local)
        }
    }
}

/// The address to aim a reply at, or `None` if this source must not be replied
/// to at all.
///
/// One function rather than an exported `unmap` beside an exported
/// `may_reply_to`, because the order between them is load-bearing and a caller
/// that gets it backwards gets a *silent* hole: the v6 rules do not see through
/// an IPv4 mapping, so checking first and unmapping second admits
/// `::ffff:255.255.255.255` — the form every IPv4 datagram arrives in on a
/// dual-stack socket. Returning the normalised address makes it impossible to
/// hold the check without also holding the normalisation.
pub(crate) fn reply_target(from: SocketAddr) -> Option<SocketAddr> {
    let from = unmap(from);
    if may_reply_to(from) {
        Some(from)
    } else {
        None
    }
}

/// What to do with a cookie reply the rate limiter has just produced.
///
/// Three variants rather than a `bool`, so the caller can log the operator's
/// misconfiguration without also logging every forged source address in a
/// flood. They are not the same event and they do not deserve the same volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CookieVerdict {
    /// Send it.
    Send,
    /// The source is an address no reply may ever be aimed at. Attacker-chosen,
    /// arbitrarily frequent, and not worth a log line.
    RefusedSource,
    /// The reply is larger than the datagram that provoked it. Determined
    /// entirely by S1/S2/S3, so it is the operator's to fix and worth saying so
    /// once.
    WouldAmplify,
}

/// Whether the cookie reply just produced for a `request_len`-byte datagram
/// from `from` may go out, given that it will occupy `reply_len` bytes on the
/// wire once its S3 prefix is attached.
///
/// # The source address
///
/// [`reply_target`], the same rule the probe responder uses, for the same
/// reason: `mac1` is computed from the server's *public* key. That key is in
/// every client configuration, so reaching this path proves nothing about who
/// sent the datagram or where the reply will land.
///
/// # The size, and why it is not [`super::probe_budget::ProbeBudget`]
///
/// Routing cookie replies through the probe responder's aggregate byte ceiling
/// is the obvious move and it is the wrong one. `verify_packet` produces a
/// cookie only once `is_under_load()` trips, so a ceiling on cookie replies is
/// a ceiling that binds *exclusively* during a flood — it would run out at the
/// one moment the replies are load-bearing, and every legitimate peer trying to
/// complete a handshake for the duration would be denied the cookie its retry
/// needs. Sharing the probe budget specifically would be worse again: a stream
/// of DNS probes could then drain the tunnel's own DoS defence.
///
/// A separate allowance for the cookie path has the same defect, only with a
/// number the operator has to guess. So there is no ceiling here. What is
/// bounded instead is the amplification factor, and it is bounded to 1: a
/// cookie reply may not be larger than the datagram that provoked it.
///
/// That is already stock WireGuard's property, held there by arithmetic nobody
/// had to write down — a 64-byte cookie reply against a 148-byte initiation is
/// an attenuator at 0.43x. AmneziaWG breaks it: S3 is prepended to the reply
/// and S1/S2 to the request, so the real ratio is `(64 + S3) / (S1 + 148)` for
/// an initiation and `(64 + S3) / (S2 + 92)` for a response. `validate` permits
/// S3 up to 65443, so the configuration space reaches a 65507-byte reply to a
/// 148-byte forgery: a ~440x reflector, pointed wherever the sender likes, and
/// unlocked by first pushing this server to 100 handshakes a second.
///
/// The bound is the request's own length rather than a constant because every
/// constant here would be invented, and this crate has already been bitten by
/// an invented factor (see `probe_reply`'s
/// `every_generator_stays_under_the_backstop_at_its_worst_case`). Parity is the
/// one number that means something on its own: below it, bouncing bytes off
/// this port costs an attacker more than sending them to the victim directly,
/// so the port is not worth using. Reflection as such does not disappear — it
/// does not disappear from stock WireGuard either, and no byte ceiling removes
/// it — but the bandwidth gain does.
///
/// # What this costs, said plainly
///
/// A configuration with a large S3 against a small S1 loses its cookie replies
/// *while under load*, and therefore loses handshakes for as long as the flood
/// lasts. That is a real regression for a real configuration, and it is why the
/// call site warns with the sizes in it rather than dropping silently: the fix
/// is to lower S3, and the operator can only make it if they are told. The
/// alternative was to keep reflecting 65 KB at a third party for every 148-byte
/// forgery, which is not the operator's to trade away.
///
/// The ordinary AmneziaWG shape is unaffected. Any configuration whose S3 is no
/// larger than its S1 and S2 is an attenuator by construction, because a cookie
/// reply is 84 bytes shorter than an initiation and 28 shorter than a response
/// before any prefix is applied — see
/// [`tests::a_prefix_no_larger_than_the_initiations_is_never_an_amplifier`].
pub(crate) fn cookie_verdict(
    from: SocketAddr,
    request_len: usize,
    reply_len: usize,
) -> CookieVerdict {
    if reply_target(from).is_none() {
        return CookieVerdict::RefusedSource;
    }
    if reply_len > request_len {
        return CookieVerdict::WouldAmplify;
    }
    CookieVerdict::Send
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::packet_sizes::{COOKIE_REPLY_SZ, HANDSHAKE_INIT_SZ, HANDSHAKE_RESP_SZ};

    fn peer(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    /// A source address is attacker-chosen. Each of these turns one forged
    /// datagram into a reply somewhere it must never go.
    #[test]
    fn refuses_source_addresses_a_reply_must_never_target() {
        let cases = [
            ("0.0.0.0:40000", "unspecified"),
            ("127.0.0.1:40000", "loopback"),
            ("224.0.0.1:40000", "multicast"),
            ("255.255.255.255:40000", "broadcast"),
            ("169.254.1.1:40000", "link-local"),
            ("0.1.2.3:40000", "0.0.0.0/8 this-network"),
            ("240.0.0.1:40000", "240.0.0.0/4 reserved"),
            ("203.0.113.5:0", "port 0"),
            ("[::]:40000", "v6 unspecified"),
            ("[::1]:40000", "v6 loopback"),
            ("[ff02::1]:40000", "v6 multicast"),
            ("[fe80::1]:40000", "v6 link-local"),
            // The dual-stack form. `Ipv6Addr::is_multicast` and friends do not
            // look inside the mapping, so these pass the v6 rules unless the
            // address is unmapped first -- and every IPv4 datagram reaching the
            // v6 socket arrives exactly like this.
            ("[::ffff:255.255.255.255]:40000", "v4-mapped broadcast"),
            ("[::ffff:224.0.0.1]:40000", "v4-mapped multicast"),
            ("[::ffff:127.0.0.1]:40000", "v4-mapped loopback"),
            ("[::ffff:169.254.1.1]:40000", "v4-mapped link-local"),
        ];
        for (addr, what) in cases {
            assert_eq!(
                reply_target(peer(addr)),
                None,
                "{} must not be replied to",
                what
            );
        }
    }

    /// The mirror of the rejection list, so that list is not vacuously passing
    /// against a function that refuses everything.
    #[test]
    fn an_ordinary_source_is_allowed_over_either_family() {
        for addr in ["203.0.113.5:40000", "[2001:db8::1]:40000"] {
            assert_eq!(
                reply_target(peer(addr)),
                Some(peer(addr)),
                "{} is an ordinary peer address",
                addr
            );
        }
    }

    /// The single door normalises as well as decides: an allowed v4-mapped
    /// source comes back as the plain IPv4 address it denotes.
    ///
    /// This is the half a caller could not have got from a bare predicate, and
    /// it is what the STUN responder puts in XOR-MAPPED-ADDRESS. A mutant that
    /// drops the `unmap` still passes the rejection list above only if the
    /// mapped-form rows are also removed; this one fails immediately.
    #[test]
    fn an_allowed_v4_mapped_source_comes_back_unmapped() {
        assert_eq!(
            reply_target(peer("[::ffff:203.0.113.5]:40000")),
            Some(peer("203.0.113.5:40000")),
            "the reply must be aimed at, and described by, the IPv4 address"
        );
    }

    /// A v6 address that merely looks like a mapping is left alone: the
    /// deprecated IPv4-*compatible* form is not something a dual-stack socket
    /// produces, and it must keep failing the v6 rules rather than being
    /// silently rewritten into an allowed IPv4 address.
    #[test]
    fn the_deprecated_v4_compatible_form_is_not_unmapped() {
        // `::203.0.113.5` is not v4-mapped, so it stays v6 -- and as a v6
        // address it is neither unspecified nor loopback nor multicast nor
        // link-local, so it is allowed *as itself*, not as 203.0.113.5.
        let compat = peer("[::203.0.113.5]:40000");
        assert_eq!(reply_target(compat), Some(compat));
    }

    /// The ~440x reflector this module exists to close, with the real numbers:
    /// the largest S3 `AmneziaConfig::validate` admits, against an initiation
    /// carrying no S1 at all.
    #[test]
    fn a_cookie_reply_larger_than_its_request_is_refused() {
        // S3 = 65443 is the maximum `validate` permits; 65443 + 64 = 65507 is
        // the whole IPv4 UDP payload.
        let request = HANDSHAKE_INIT_SZ; // S1 = 0
        let reply = 65443 + COOKIE_REPLY_SZ;
        assert_eq!(
            cookie_verdict(peer("203.0.113.5:40000"), request, reply),
            CookieVerdict::WouldAmplify,
            "{} bytes in reply to {} is a {}x amplifier",
            reply,
            request,
            reply / request
        );
    }

    /// Parity is allowed; one byte over is not. Asserted as the boundary rather
    /// than as two comfortable cases, because the boundary is the whole rule.
    #[test]
    fn the_bound_is_the_requests_own_length_exactly() {
        let from = peer("203.0.113.5:40000");
        assert_eq!(cookie_verdict(from, 268, 267), CookieVerdict::Send);
        assert_eq!(cookie_verdict(from, 268, 268), CookieVerdict::Send);
        assert_eq!(
            cookie_verdict(from, 268, 269),
            CookieVerdict::WouldAmplify,
            "one byte over parity is over"
        );
    }

    /// The configurations real deployments run are untouched.
    ///
    /// A cookie reply is 84 bytes shorter than an initiation and 28 shorter
    /// than a response before any prefix is applied, so any S3 no larger than
    /// S1 (or S2) is an attenuator by construction. Computed from the protocol
    /// constants rather than from remembered numbers, so a change to either
    /// packet size is caught here instead of in production.
    #[test]
    fn a_prefix_no_larger_than_the_initiations_is_never_an_amplifier() {
        let from = peer("203.0.113.5:40000");
        // 65359 is the largest S1 `AmneziaConfig::validate` accepts, so every
        // row here is a configuration an operator could actually set -- the
        // claim is about real configurations, not about arithmetic.
        for s in [0usize, 15, 110, 120, 1000, 65359] {
            for (base, what) in [
                (HANDSHAKE_INIT_SZ, "initiation"),
                (HANDSHAKE_RESP_SZ, "response"),
            ] {
                assert_eq!(
                    cookie_verdict(from, s + base, s + COOKIE_REPLY_SZ),
                    CookieVerdict::Send,
                    "S3 = S1 = {} against a{} {}-byte {} must still be answered",
                    s,
                    if what == "initiation" { "n" } else { "" },
                    base,
                    what
                );
            }
        }
    }

    /// The address rule applies to cookie replies too, and it applies *first*:
    /// a perfectly-sized reply to a broadcast source is still refused.
    ///
    /// Without this, a mutant that checks only the size passes every other test
    /// in this module.
    #[test]
    fn a_well_sized_cookie_reply_is_still_refused_to_a_forbidden_source() {
        for addr in ["255.255.255.255:40000", "[::ffff:224.0.0.1]:40000"] {
            assert_eq!(
                cookie_verdict(peer(addr), 268, 174),
                CookieVerdict::RefusedSource,
                "{} must not be replied to at any size",
                addr
            );
        }
    }
}
