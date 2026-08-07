// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// For `conforming_initiation` only, and gated exactly as it is: its caller is
// `device::probe_reply`, which does not exist without the `device` feature.
#[cfg(all(test, feature = "device"))]
use super::HANDSHAKE_INIT;
use super::{
    handshake::ObfuscationRanges, COOKIE_REPLY_SZ, DATA_OVERHEAD_SZ, HANDSHAKE_INIT_SZ,
    HANDSHAKE_RESP_SZ,
};
use crate::noise::errors::WireGuardError;
use rand_core::RngCore;
use std::convert::{TryFrom, TryInto};
use std::time::Duration;

const DNS_OPT_FIXED_LEN: usize = 11;
const DNS_OPT_MIN_WIRE_SIZE: usize = DNS_OPT_FIXED_LEN + 4;
const DEFAULT_JUNK_PACKET_SIZE_MIN: u16 = 50;
const DEFAULT_JUNK_PACKET_SIZE_MAX: u16 = 1000;
const MAX_JUNK_PACKET_COUNT: u16 = 128;
const MAX_JUNK_PACKET_SIZE: u16 = 1280;
const MAX_JUNK_PACKET_DELAY_MS: u16 = 200;
/// Largest datagram that can actually be sent: the IPv4 UDP payload limit,
/// `65535 - 20 (IP header) - 8 (UDP header)`. IPv6 allows 27 bytes more, but the
/// stricter bound is used so a configuration validated once is sendable over
/// either family — a device may be listening on both.
///
/// The kernel module bounds the same sizes by `MESSAGE_MAX_SIZE = 65535`
/// (`amneziawg-linux-kernel-module/src/messages.h:132`), which is the protocol
/// ceiling rather than the transport one. The 28-byte difference is deliberate:
/// a configuration in that window passes the kernel's check and then fails at
/// send time with `EMSGSIZE`, so it does not work there either. Rejecting it up
/// front is not a parity break — every configuration that *functions* on the
/// kernel module is still accepted here.
const MAX_SENDABLE_DATAGRAM: usize = 65535 - 20 - 8;
const DNS_JUNK_SIZE_MIN: usize = 50;
const DNS_JUNK_SIZE_MAX: usize = 200;
const QUIC_JUNK_SIZE_MIN: usize = 1200;
const QUIC_JUNK_SIZE_MAX: usize = 1252;
const SIP_JUNK_SIZE_MIN: usize = 200;
const SIP_JUNK_SIZE_MAX: usize = 1200;
const STUN_JUNK_SIZE_MIN: usize = 28;
const STUN_JUNK_SIZE_MAX: usize = 100;
// RFC 5389 STUN magic cookie, present at bytes 4..8 of every STUN message.
// Imported rather than restated: `crate::noise::imitation::stun::MAGIC_COOKIE`
// is the crate's single definition. A private alias, not a re-export -- that
// would be `pub use` and would put the constant in this module's public API.
//
// A line comment, not a doc comment: rustdoc does not process docs on a
// private `use`, so a `///` here documents nothing and cannot be checked.
use crate::noise::imitation::stun::MAGIC_COOKIE as STUN_MAGIC_COOKIE;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum AmneziaImitationProtocol {
    #[default]
    None = 0,
    Dns = 1,
    Quic = 2,
    Sip = 3,
    Stun = 4,
}

impl TryFrom<u8> for AmneziaImitationProtocol {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Dns),
            2 => Ok(Self::Quic),
            3 => Ok(Self::Sip),
            4 => Ok(Self::Stun),
            _ => Err(()),
        }
    }
}

impl AmneziaImitationProtocol {
    /// Every variant, so a caller offering these as choices cannot fall behind
    /// the enum. `boringtun-cli` builds its `--imitate-protocol` value list from
    /// this rather than restating it.
    pub const ALL: [Self; 5] = [Self::None, Self::Dns, Self::Quic, Self::Sip, Self::Stun];

    /// The name used on the command line and in `Ip =` config values.
    ///
    /// A `match` over `self` rather than a lookup table: adding a variant fails
    /// to compile here, which is the whole point. The previous arrangement had
    /// the CLI map these strings with a `_ =>` catch-all, so a new variant that
    /// nobody wired up silently meant "no imitation".
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Dns => "dns",
            Self::Quic => "quic",
            Self::Sip => "sip",
            Self::Stun => "stun",
        }
    }

    /// Does this protocol's cover traffic carry a hostname?
    ///
    /// `None` and `Stun` do not, and [`AmneziaImitation::new`] silently drops a
    /// domain supplied with them. A caller that took one from an operator should
    /// use this to say so rather than let it vanish.
    pub fn uses_domain(self) -> bool {
        matches!(self, Self::Dns | Self::Sip | Self::Quic)
    }
}

impl std::str::FromStr for AmneziaImitationProtocol {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `.iter().copied()`, not `.into_iter()`: in edition 2018 the latter on
        // an array yields references, so this would be a `Result<&Self, _>`.
        Self::ALL
            .iter()
            .copied()
            .find(|p| p.as_str() == s)
            .ok_or(())
    }
}

/// Browser fingerprint for QUIC protocol imitation. All variants emit a full
/// browser-fingerprinted QUIC Initial; `Default` resolves to curl, matching
/// wgbooster's default browser when a domain is set but `Ib` is omitted.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum AmneziaImitationBrowser {
    #[default]
    Default = 0,
    Chrome = 1,
    Firefox = 2,
    Curl = 3,
    Random = 4,
}

impl TryFrom<u8> for AmneziaImitationBrowser {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Default),
            1 => Ok(Self::Chrome),
            2 => Ok(Self::Firefox),
            3 => Ok(Self::Curl),
            4 => Ok(Self::Random),
            _ => Err(()),
        }
    }
}

impl AmneziaImitationBrowser {
    /// Map to a QUIC generator profile. `Default` resolves to curl, matching
    /// wgbooster's default browser when a domain is set but no `Ib` is given —
    /// so an omitted browser still produces a full QUIC Initial rather than the
    /// lightweight QUIC-shaped junk.
    fn to_quic(self) -> crate::noise::quic::profiles::BrowserProfile {
        use crate::noise::quic::profiles::BrowserProfile;
        match self {
            AmneziaImitationBrowser::Default | AmneziaImitationBrowser::Curl => {
                BrowserProfile::Curl
            }
            AmneziaImitationBrowser::Chrome => BrowserProfile::Chrome,
            AmneziaImitationBrowser::Firefox => BrowserProfile::Firefox,
            AmneziaImitationBrowser::Random => BrowserProfile::Random,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmneziaImitation {
    pub(crate) protocol: AmneziaImitationProtocol,
    domain: Option<String>,
    pub(crate) browser: AmneziaImitationBrowser,
}

impl AmneziaImitation {
    pub fn new(
        protocol: AmneziaImitationProtocol,
        domain: Option<String>,
        browser: AmneziaImitationBrowser,
    ) -> Self {
        // DNS QNAMEs and SIP URIs need a strict LDH host (the latter is spliced
        // into text headers, so this also prevents injection). The QUIC SNI is a
        // length-prefixed TLS extension, so it accepts UTF-8/IDN like wgbooster.
        // Invalid hosts are dropped (a random one is generated at emit time).
        let domain = match protocol {
            AmneziaImitationProtocol::Dns | AmneziaImitationProtocol::Sip => {
                domain.filter(|domain| is_valid_imitation_host(domain))
            }
            AmneziaImitationProtocol::Quic => domain.filter(|domain| is_valid_quic_sni(domain)),
            _ => None,
        };
        // Browser only applies to QUIC.
        let browser = if protocol == AmneziaImitationProtocol::Quic {
            browser
        } else {
            AmneziaImitationBrowser::Default
        };

        Self {
            protocol,
            domain,
            browser,
        }
    }

    /// The domain that survived validation, if any.
    ///
    /// `pub` so a caller can tell whether the hostname it supplied was actually
    /// kept: [`Self::new`] drops an invalid host and falls back to a randomly
    /// generated one at emit time, which is a silent substitution an operator
    /// would otherwise only discover in a packet capture.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}

/// A conforming AmneziaWG handshake initiation, before and after
/// [`AmneziaConfig::prepend_outbound`].
///
/// Lives here, next to the padding rules, because `device::probe_reply`'s
/// ordering test needs a datagram that is *simultaneously* valid AmneziaWG and a
/// valid DNS query — which is exactly what this module produces under `ip=dns`.
/// Building it there instead meant exporting `HANDSHAKE_INIT` and
/// `HANDSHAKE_INIT_SZ` crate-wide for a test, permanently widening two
/// protocol constants that nothing in production needs outside `noise`.
///
/// Gated on `device` as well as `test`, for the reason [`super::packet_sizes`]
/// gives: the only caller is behind that feature, so a test build without it
/// carries a `dead_code` warning for this function -- and `cargo hack test
/// --each-feature`, which CI runs, compiles exactly that configuration.
#[cfg(all(test, feature = "device"))]
pub(crate) fn conforming_initiation(
    cfg: &AmneziaConfig,
    obf: ObfuscationRanges,
    rng: &mut impl RngCore,
) -> (Vec<u8>, Vec<u8>) {
    let mut original = vec![0u8; HANDSHAKE_INIT_SZ];
    original[..4].copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
    for (i, byte) in original[4..].iter_mut().enumerate() {
        *byte = (i as u8) ^ 0x5a;
    }

    let mut buffer = vec![0u8; HANDSHAKE_INIT_SZ + 1280];
    buffer[..HANDSHAKE_INIT_SZ].copy_from_slice(&original);
    let padded = cfg
        .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, rng)
        .expect("S1 must leave room for the initiation")
        .to_vec();

    (original, padded)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmneziaConfig {
    pub(crate) init_packet_junk_size: u16,
    pub(crate) response_packet_junk_size: u16,
    pub(crate) cookie_packet_junk_size: u16,
    pub(crate) transport_packet_junk_size: u16,
    pub(crate) pre_handshake_junk: AmneziaPreHandshakeJunk,
    pub(crate) imitation: AmneziaImitation,
    /// Suppress the client-only pre-handshake burst (Jc junk packets and the
    /// protocol imitation sequence) while keeping every other AmneziaWG
    /// behaviour. See [`AmneziaConfig::as_responder`].
    pub(crate) suppress_pre_handshake: bool,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct AmneziaPreHandshakeJunk {
    pub(crate) packet_count: u16,
    pub(crate) packet_size_min: u16,
    pub(crate) packet_size_max: u16,
    pub(crate) packet_delay_ms: u16,
}

impl AmneziaPreHandshakeJunk {
    pub fn new(
        packet_count: u16,
        packet_size_min: u16,
        packet_size_max: u16,
        delay_ms: u16,
    ) -> Self {
        let packet_count = if packet_count <= MAX_JUNK_PACKET_COUNT {
            packet_count
        } else {
            0
        };

        let (packet_size_min, packet_size_max) = if packet_count == 0 {
            (packet_size_min, packet_size_max)
        } else if packet_size_min == 0 && packet_size_max == 0 {
            (DEFAULT_JUNK_PACKET_SIZE_MIN, DEFAULT_JUNK_PACKET_SIZE_MAX)
        } else if packet_size_min > 0
            && packet_size_min <= packet_size_max
            && packet_size_max <= MAX_JUNK_PACKET_SIZE
        {
            (packet_size_min, packet_size_max)
        } else {
            (DEFAULT_JUNK_PACKET_SIZE_MIN, DEFAULT_JUNK_PACKET_SIZE_MAX)
        };

        let packet_delay_ms = if delay_ms <= MAX_JUNK_PACKET_DELAY_MS {
            delay_ms
        } else {
            0
        };

        Self {
            packet_count,
            packet_size_min,
            packet_size_max,
            packet_delay_ms,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.packet_count > 0
    }

    pub fn delay(&self) -> Duration {
        Duration::from_millis(self.packet_delay_ms as u64)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum PacketKind {
    HandshakeInit,
    HandshakeResponse,
    CookieReply,
    TransportData,
}

impl AmneziaConfig {
    /// Create a config with the AmneziaWG S1-S4 junk prefix sizes.
    ///
    /// `s1`/`s2`/`s3`/`s4` are the number of junk bytes prepended to handshake
    /// initiation, handshake response, cookie reply, and transport-data packets
    /// respectively. They are used verbatim and are not clamped: callers must
    /// size their output buffers to fit the base WireGuard packet plus the
    /// configured prefix, otherwise `prepend_outbound` (and therefore
    /// `Tunn::encapsulate`) returns [`WireGuardError::DestinationBufferTooSmall`].
    pub fn new(s1: u16, s2: u16, s3: u16, s4: u16) -> Self {
        Self {
            init_packet_junk_size: s1,
            response_packet_junk_size: s2,
            cookie_packet_junk_size: s3,
            transport_packet_junk_size: s4,
            pre_handshake_junk: AmneziaPreHandshakeJunk::default(),
            imitation: AmneziaImitation::default(),
            suppress_pre_handshake: false,
        }
    }

    pub fn with_pre_handshake_junk(
        mut self,
        packet_count: u16,
        packet_size_min: u16,
        packet_size_max: u16,
        delay_ms: u16,
    ) -> Self {
        self.pre_handshake_junk =
            AmneziaPreHandshakeJunk::new(packet_count, packet_size_min, packet_size_max, delay_ms);
        self
    }

    pub fn with_protocol_imitation(
        mut self,
        protocol: AmneziaImitationProtocol,
        domain: Option<String>,
    ) -> Self {
        self.imitation = AmneziaImitation::new(protocol, domain, AmneziaImitationBrowser::Default);
        self
    }

    /// As [`Self::with_protocol_imitation`], plus a browser fingerprint for QUIC.
    pub fn with_protocol_imitation_browser(
        mut self,
        protocol: AmneziaImitationProtocol,
        domain: Option<String>,
        browser: AmneziaImitationBrowser,
    ) -> Self {
        self.imitation = AmneziaImitation::new(protocol, domain, browser);
        self
    }

    /// Check that every S-prefix can coexist with the packet it precedes.
    ///
    /// [`Self::new`] deliberately does not clamp, because the sizes are part of
    /// the wire contract and a peer configured differently must still be
    /// describable. But a configuration whose prefix cannot fit alongside its
    /// base packet can never emit a valid datagram: `prepend_outbound` returns
    /// [`WireGuardError::DestinationBufferTooSmall`] forever, which surfaces as
    /// a tunnel that simply never completes a handshake, with nothing pointing
    /// at the configuration. Callers accepting operator input should reject it
    /// at the point of entry instead.
    ///
    /// The bounds correspond to the kernel module's own validation
    /// (`amneziawg-linux-kernel-module/src/device.c:584-601`), but are 28 bytes
    /// stricter: the kernel bounds by the protocol ceiling
    /// (`MESSAGE_MAX_SIZE = 65535`) while this uses `MAX_SENDABLE_DATAGRAM`,
    /// what a UDP socket can actually carry.
    ///
    /// The relationship is therefore one-way, not symmetric: every
    /// configuration that *functions* on the kernel module is accepted here,
    /// but a configuration landing in the 28-byte gap is accepted by the kernel
    /// and rejected here. Nothing is lost — such a configuration fails on the
    /// kernel too, at send time with `EMSGSIZE`, so it never worked there
    /// either. See `MAX_SENDABLE_DATAGRAM` for the arithmetic.
    pub fn validate(&self) -> Result<(), String> {
        for (label, junk, base) in [
            ("S1", self.init_packet_junk_size, HANDSHAKE_INIT_SZ),
            ("S2", self.response_packet_junk_size, HANDSHAKE_RESP_SZ),
            ("S3", self.cookie_packet_junk_size, COOKIE_REPLY_SZ),
            ("S4", self.transport_packet_junk_size, DATA_OVERHEAD_SZ),
        ] {
            if junk as usize + base > MAX_SENDABLE_DATAGRAM {
                return Err(format!(
                    "{} is too large: {} junk bytes + {} packet bytes exceed the {}-byte maximum datagram",
                    label, junk, base, MAX_SENDABLE_DATAGRAM
                ));
            }
        }
        Ok(())
    }

    /// Adapt this configuration for the responder (server) side of a tunnel.
    ///
    /// A server must *tolerate* a client's pre-handshake camouflage but must
    /// never emit it: the Jc junk burst and the protocol imitation sequence are
    /// things a client sends to open a conversation. Emitting them from a
    /// responder is both directionally wrong — it looks like the server is
    /// opening a QUIC/DNS/SIP/STUN exchange with its own peer — and slow, since
    /// the queue drains one datagram per `update_timers` tick, delaying any
    /// server-initiated handshake by the length of the sequence.
    ///
    /// Everything else is preserved, including the imitation protocol itself:
    /// S1-S4 padding is still filled with protocol-shaped bytes
    /// (`fill_outbound_junk`), so the server's own traffic keeps the
    /// same byte distribution as the client's. Only the *standalone* datagrams
    /// are suppressed.
    pub fn as_responder(mut self) -> Self {
        self.suppress_pre_handshake = true;
        self
    }

    /// True when a full protocol-natural imitation sequence should be emitted
    /// for the pre-handshake phase. DNS/SIP/STUN/QUIC all qualify (QUIC's omitted
    /// browser defaults to curl, matching wgbooster); only `None` does not.
    pub(crate) fn has_imitation_sequence(&self) -> bool {
        self.imitation.protocol != AmneziaImitationProtocol::None
    }

    /// True when this endpoint should emit a pre-handshake burst at all —
    /// false for a responder, and for a client with neither Jc nor imitation.
    pub(crate) fn emits_pre_handshake(&self) -> bool {
        !self.suppress_pre_handshake
            && (self.pre_handshake_junk.is_enabled() || self.has_imitation_sequence())
    }

    /// The configured imitation host, or a generated random one (DNS query name
    /// / SIP URI host / QUIC SNI).
    fn imitation_host(&self, rng: &mut impl RngCore) -> String {
        self.imitation
            .domain()
            .map(str::to_owned)
            .unwrap_or_else(|| random_imitation_domain(rng))
    }

    /// Generate the standalone imitation datagram sequence for the pre-handshake
    /// phase, each paired with the delay to wait *before* emitting it. Imitation
    /// ignores the generic Jd delay and uses protocol-natural timing (the first
    /// datagram always has zero delay): DNS sends A+AAAA in parallel then HTTPS
    /// after 15 ms; SIP waits 20 ms before the CANCEL; STUN waits 15 ms before
    /// the nomination check; QUIC Initials go back-to-back.
    pub(crate) fn pre_handshake_imitation_datagrams(
        &self,
        rng: &mut impl RngCore,
    ) -> std::collections::VecDeque<(Duration, Vec<u8>)> {
        use crate::noise::imitation::{dns, sip, stun};

        let (datagrams, delays_ms): (Vec<Vec<u8>>, &[u16]) = match self.imitation.protocol {
            AmneziaImitationProtocol::Dns => {
                (dns::generate(&self.imitation_host(rng), rng), &[0, 0, 15])
            }
            AmneziaImitationProtocol::Sip => {
                (sip::generate(&self.imitation_host(rng), rng), &[0, 20])
            }
            AmneziaImitationProtocol::Stun => (stun::generate(rng), &[0, 15]),
            AmneziaImitationProtocol::Quic => {
                let browser = self.imitation.browser.to_quic();
                let datagrams = crate::noise::quic::generator::generate_client_initials(
                    browser,
                    &self.imitation_host(rng),
                    rng,
                );
                (datagrams, &[])
            }
            AmneziaImitationProtocol::None => (Vec::new(), &[]),
        };

        datagrams
            .into_iter()
            .enumerate()
            .map(|(i, datagram)| {
                let ms = delays_ms.get(i).copied().unwrap_or(0);
                (Duration::from_millis(ms as u64), datagram)
            })
            .collect()
    }

    fn inbound_junk_size(&self, kind: PacketKind) -> usize {
        (match kind {
            PacketKind::HandshakeInit => self.init_packet_junk_size,
            PacketKind::HandshakeResponse => self.response_packet_junk_size,
            PacketKind::CookieReply => self.cookie_packet_junk_size,
            PacketKind::TransportData => self.transport_packet_junk_size,
        }) as usize
    }

    fn outbound_junk_size(&self, kind: PacketKind) -> usize {
        self.inbound_junk_size(kind)
    }

    fn read_tag(packet: &[u8], offset: usize) -> Option<u32> {
        let tag = packet.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(tag.try_into().ok()?))
    }

    fn tag_matches(obf: ObfuscationRanges, kind: PacketKind, tag: u32) -> bool {
        match kind {
            PacketKind::HandshakeInit => obf.matches_h1(tag),
            PacketKind::HandshakeResponse => obf.matches_h2(tag),
            PacketKind::CookieReply => obf.matches_h3(tag),
            PacketKind::TransportData => obf.matches_h4(tag),
        }
    }

    fn inbound_kind_at_offset(
        &self,
        obf: ObfuscationRanges,
        packet: &[u8],
        kind: PacketKind,
        base_size: usize,
    ) -> bool {
        let junk_size = self.inbound_junk_size(kind);
        if packet.len() != junk_size + base_size {
            return false;
        }
        Self::read_tag(packet, junk_size)
            .map(|tag| Self::tag_matches(obf, kind, tag))
            .unwrap_or(false)
    }

    /// Strip the AmneziaWG junk prefix from an inbound datagram, or reject it.
    ///
    /// Returns `None` when the datagram matches no configured packet shape.
    ///
    /// The padding rule is *per packet kind*, not global: a kind whose S is
    /// non-zero must arrive padded, while a kind whose S is zero must arrive
    /// unpadded. A configuration with `S1 = 15, S4 = 0` therefore rejects a
    /// bare initiation and accepts a bare transport packet, and both are
    /// correct. Rejecting everything unpadded would break the second case.
    ///
    /// Handing a non-matching datagram back unmodified -- as this used to --
    /// let the caller re-read the tag at offset 0 and accept it, which made
    /// the S-prefix an obfuscation rather than an input filter. The kernel
    /// module drops such a datagram outright (`prepare_awg_message`,
    /// `src/receive.c`).
    ///
    /// A datagram cannot match two kinds: `ObfuscationRanges::new` validates
    /// the H ranges as non-overlapping, and the three handshake kinds have
    /// distinct fixed sizes. With every S at zero these tests reduce to the
    /// same (tag, length) pairs `Tunn::parse_incoming_packet` applies, so
    /// plain WireGuard is unaffected.
    pub(crate) fn strip_inbound<'a>(
        &self,
        obf: ObfuscationRanges,
        packet: &'a [u8],
    ) -> Option<&'a [u8]> {
        for (kind, base) in [
            (PacketKind::HandshakeInit, HANDSHAKE_INIT_SZ),
            (PacketKind::HandshakeResponse, HANDSHAKE_RESP_SZ),
            (PacketKind::CookieReply, COOKIE_REPLY_SZ),
        ] {
            if self.inbound_kind_at_offset(obf, packet, kind, base) {
                return Some(&packet[self.inbound_junk_size(kind)..]);
            }
        }

        // Transport data is variable length, so this is a minimum rather than
        // an exact size. With S4 = 0 the offset is 0 and this is exactly the
        // vanilla check.
        let junk = self.inbound_junk_size(PacketKind::TransportData);
        if packet.len() >= junk + DATA_OVERHEAD_SZ
            && Self::read_tag(packet, junk)
                .map(|tag| Self::tag_matches(obf, PacketKind::TransportData, tag))
                .unwrap_or(false)
        {
            return Some(&packet[junk..]);
        }

        None
    }

    fn classify_outbound(&self, obf: ObfuscationRanges, packet: &[u8]) -> Option<PacketKind> {
        let tag = Self::read_tag(packet, 0)?;
        match packet.len() {
            HANDSHAKE_INIT_SZ if obf.matches_h1(tag) => Some(PacketKind::HandshakeInit),
            HANDSHAKE_RESP_SZ if obf.matches_h2(tag) => Some(PacketKind::HandshakeResponse),
            COOKIE_REPLY_SZ if obf.matches_h3(tag) => Some(PacketKind::CookieReply),
            len if len >= DATA_OVERHEAD_SZ && obf.matches_h4(tag) => {
                Some(PacketKind::TransportData)
            }
            _ => None,
        }
    }

    /// How many bytes a `cookie_len`-byte cookie reply will occupy on the wire,
    /// S3 prefix included.
    ///
    /// Exists so the ingress path can decide whether the reply is an amplifier
    /// *before* [`Self::prepend_outbound`] generates junk for it. With S3 near
    /// its 65443-byte maximum, filling a prefix for a reply that policy then
    /// refuses would itself be the flood — one forged 148-byte initiation per
    /// 65 KB of keystream, which is a cheaper attack than the amplification it
    /// was meant to prevent.
    ///
    /// Reads the prefix size through [`Self::outbound_junk_size`], the same
    /// accessor `prepend_outbound` uses, so the prediction cannot drift from
    /// the production by way of two spellings of one lookup. What it still has
    /// to assume is the packet *kind*, which `prepend_outbound` derives from
    /// the tag on the wire, so
    /// [`tests::the_predicted_cookie_reply_length_is_the_one_actually_produced`]
    /// pins the two together.
    ///
    /// Gated because the ingress path is the only caller: without `device` this
    /// is dead code, and a crate built without the feature would carry a
    /// `dead_code` warning for it. `test` is in the list so the test above still
    /// runs on a default-feature `cargo test`.
    #[cfg(any(test, feature = "device"))]
    pub(crate) fn cookie_reply_len(&self, cookie_len: usize) -> usize {
        cookie_len.saturating_add(self.outbound_junk_size(PacketKind::CookieReply))
    }

    /// The S sizes at which a cookie reply would be larger than the packet that
    /// provokes it, if there are any.
    ///
    /// Returns `(kind, request_len, reply_len)` for the first packet kind that
    /// amplifies, where `kind` is `"S1"` (an initiation) or `"S2"` (a response).
    ///
    /// `device::reply_policy::cookie_verdict` suppresses such a reply, because a
    /// cookie reply aimed at a forged source is a reflector and the ratio is
    /// fixed entirely by this configuration — an attacker cannot influence it.
    /// The cost is real: the peer never learns the cookie, so it can never
    /// produce a valid mac2, and every one of its handshakes fails for as long
    /// as the device stays over `HANDSHAKE_RATE_LIMIT`.
    ///
    /// This exists so the operator hears about that when they set the sizes,
    /// rather than during the flood. The condition is decidable from S1/S2/S3
    /// alone — `64 + S3 > 148 + S1` for an initiation, `64 + S3 > 92 + S2` for a
    /// response — so there is no reason to discover it at send time.
    ///
    /// It deliberately does **not** reject. The AmneziaWG kernel module accepts
    /// these combinations, and a config this fork refuses but the reference
    /// implementation runs would be an interoperability break for a
    /// configuration that is merely unwise.
    ///
    /// Gated with `cookie_reply_len` above: `device::api` is the only caller.
    #[cfg(any(test, feature = "device"))]
    pub(crate) fn cookie_reply_amplifies(&self) -> Option<(&'static str, usize, usize)> {
        let reply = COOKIE_REPLY_SZ + self.cookie_packet_junk_size as usize;
        for (label, junk, base) in [
            ("S1", self.init_packet_junk_size, HANDSHAKE_INIT_SZ),
            ("S2", self.response_packet_junk_size, HANDSHAKE_RESP_SZ),
        ] {
            let request = base + junk as usize;
            if reply > request {
                return Some((label, request, reply));
            }
        }
        None
    }

    pub(crate) fn prepend_outbound<'a>(
        &self,
        obf: ObfuscationRanges,
        buffer: &'a mut [u8],
        packet_size: usize,
        rng: &mut impl RngCore,
    ) -> Result<&'a mut [u8], WireGuardError> {
        let packet = buffer
            .get(..packet_size)
            .ok_or(WireGuardError::DestinationBufferTooSmall)?;
        let Some(kind) = self.classify_outbound(obf, packet) else {
            return Ok(&mut buffer[..packet_size]);
        };

        let junk_size = self.outbound_junk_size(kind);
        if junk_size == 0 {
            return Ok(&mut buffer[..packet_size]);
        }

        let new_size = packet_size
            .checked_add(junk_size)
            .ok_or(WireGuardError::DestinationBufferTooSmall)?;
        if buffer.len() < new_size {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        buffer.copy_within(0..packet_size, junk_size);
        self.fill_outbound_junk(&mut buffer[..junk_size], packet_size, rng);
        Ok(&mut buffer[..new_size])
    }

    pub fn fill_pre_handshake_junk<'a>(
        &self,
        buffer: &'a mut [u8],
        rng: &mut impl RngCore,
    ) -> Result<&'a mut [u8], WireGuardError> {
        if !self.pre_handshake_junk.is_enabled() {
            return Ok(&mut buffer[..0]);
        }

        let size = self.pre_handshake_junk_size(rng);
        if buffer.len() < size {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let packet = &mut buffer[..size];
        match self.imitation.protocol {
            AmneziaImitationProtocol::None => fill_random(packet, rng),
            AmneziaImitationProtocol::Dns => fill_dns(packet, 0, self.imitation.domain(), rng),
            AmneziaImitationProtocol::Quic => fill_quic_initial(packet, rng),
            AmneziaImitationProtocol::Sip => fill_sip(packet, self.imitation.domain(), rng),
            AmneziaImitationProtocol::Stun => fill_stun(packet, rng),
        }

        Ok(packet)
    }

    fn pre_handshake_junk_size(&self, rng: &mut impl RngCore) -> usize {
        match self.imitation.protocol {
            AmneziaImitationProtocol::None => random_usize_inclusive(
                self.pre_handshake_junk.packet_size_min as usize,
                self.pre_handshake_junk.packet_size_max as usize,
                rng,
            ),
            AmneziaImitationProtocol::Dns => {
                random_usize_inclusive(DNS_JUNK_SIZE_MIN, DNS_JUNK_SIZE_MAX, rng)
            }
            AmneziaImitationProtocol::Quic => {
                random_usize_inclusive(QUIC_JUNK_SIZE_MIN, QUIC_JUNK_SIZE_MAX, rng)
            }
            AmneziaImitationProtocol::Sip => {
                random_usize_inclusive(SIP_JUNK_SIZE_MIN, SIP_JUNK_SIZE_MAX, rng)
            }
            AmneziaImitationProtocol::Stun => {
                random_usize_inclusive(STUN_JUNK_SIZE_MIN, STUN_JUNK_SIZE_MAX, rng)
            }
        }
    }

    fn fill_outbound_junk(&self, dst: &mut [u8], trailing_size: usize, rng: &mut impl RngCore) {
        match self.imitation.protocol {
            AmneziaImitationProtocol::None => fill_random(dst, rng),
            protocol => {
                fill_protocol_like(protocol, self.imitation.domain(), dst, trailing_size, rng)
            }
        }
    }
}

/// Generate a plausible random host name when no domain is configured for an
/// imitation that needs one (DNS query name, SIP URI host, QUIC SNI).
fn random_imitation_domain(rng: &mut impl RngCore) -> String {
    const TLDS: [&str; 4] = ["com", "net", "org", "io"];
    let label_len = 7 + (rng.next_u32() % 10) as usize; // 7..=16 chars
    let mut host = String::with_capacity(label_len + 4);
    for _ in 0..label_len {
        host.push((b'a' + (rng.next_u32() % 26) as u8) as char);
    }
    host.push('.');
    host.push_str(TLDS[(rng.next_u32() as usize) % TLDS.len()]);
    host
}

fn random_usize_inclusive(min: usize, max: usize, rng: &mut impl RngCore) -> usize {
    if min >= max {
        return min;
    }

    let range_size = (max - min) as u64 + 1;
    let threshold = u64::MAX - (u64::MAX % range_size);
    loop {
        let val = rng.next_u64();
        if val < threshold {
            return min + (val % range_size) as usize;
        }
    }
}

fn fill_protocol_like(
    protocol: AmneziaImitationProtocol,
    domain: Option<&str>,
    dst: &mut [u8],
    trailing_size: usize,
    rng: &mut impl RngCore,
) {
    match protocol {
        AmneziaImitationProtocol::None => fill_random(dst, rng),
        AmneziaImitationProtocol::Dns => fill_dns(dst, trailing_size, domain, rng),
        // Always a 1-RTT short header, for every packet kind. A long header
        // carries a length field that would have to frame the bytes that
        // follow -- but those are the immutable WireGuard packet, which this
        // prefix cannot describe, so any long-header form parses as malformed.
        // A short header has no version or length field, so the remaining
        // bytes are indistinguishable from encrypted 1-RTT payload.
        //
        // The S-region is also far too small for a valid Initial: S2 + 92 and
        // S3 + 64 are nowhere near the 1200-byte minimum of RFC 9000 §14.1
        // (contrast `pre_handshake_junk_size`, where the QUIC branch picks
        // QUIC_JUNK_SIZE_MIN..=MAX = 1200..=1252 precisely so that a
        // long-header Initial is legal). And S2/S3 travel responder -> peer,
        // so emitting an Initial there inverts the direction of a real QUIC
        // handshake, where the Initial is the client's first packet.
        AmneziaImitationProtocol::Quic => fill_quic_short(dst, rng),
        AmneziaImitationProtocol::Sip => fill_sip(dst, domain, rng),
        AmneziaImitationProtocol::Stun => fill_stun(dst, rng),
    }
}

fn fill_random(dst: &mut [u8], rng: &mut impl RngCore) {
    let mut chunks = dst.chunks_exact_mut(4);
    for chunk in &mut chunks {
        chunk.copy_from_slice(&rng.next_u32().to_le_bytes());
    }
    let rem = chunks.into_remainder();
    if !rem.is_empty() {
        let bytes = rng.next_u32().to_le_bytes();
        rem.copy_from_slice(&bytes[..rem.len()]);
    }
}

fn random_byte(rng: &mut impl RngCore) -> u8 {
    (rng.next_u32() & 0xff) as u8
}

fn fill_quic_short(dst: &mut [u8], rng: &mut impl RngCore) {
    if dst.is_empty() {
        return;
    }

    let spin = ((rng.next_u32() >> 8) & 0x01) as u8;
    let key_phase = ((rng.next_u32() >> 8) & 0x01) as u8;
    let pn_len = (rng.next_u32() & 0x03) as u8;
    dst[0] = 0x40 | (spin << 5) | (key_phase << 2) | pn_len;
    for byte in &mut dst[1..] {
        *byte = random_byte(rng);
    }
}

fn fill_quic_initial(dst: &mut [u8], rng: &mut impl RngCore) {
    fill_random(dst, rng);
    if !dst.is_empty() {
        dst[0] = 0xc0 | (rng.next_u32() & 0x03) as u8;
    }
    if dst.len() >= 5 {
        dst[1] = 0x00;
        dst[2] = 0x00;
        dst[3] = 0x00;
        dst[4] = 0x01;
    }
    if dst.len() >= 6 {
        dst[5] = ((rng.next_u32() % 17) + 4) as u8;
    }
}

fn fill_stun(dst: &mut [u8], rng: &mut impl RngCore) {
    fill_random(dst, rng);
    let size = dst.len();

    if size >= 2 {
        dst[0] = 0x00;
        dst[1] = 0x01;
    }

    let body = if size > 20 { (size - 20) & !0x03 } else { 0 };
    let value_len = if body >= 4 { (body - 4).min(124) } else { 0 };
    let attr_len = if body >= 4 { 4 + value_len } else { 0 };

    if size >= 4 {
        let len = attr_len as u16;
        dst[2] = (len >> 8) as u8;
        dst[3] = len as u8;
    }
    if size >= 8 {
        dst[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
    }
    if size > 8 {
        for byte in &mut dst[8..size.min(20)] {
            *byte = random_byte(rng);
        }
    }
    if attr_len >= 4 {
        let value_len = value_len as u16;
        dst[20] = 0x80;
        dst[21] = 0x22;
        dst[22] = (value_len >> 8) as u8;
        dst[23] = value_len as u8;
        for byte in &mut dst[24..24 + value_len as usize] {
            *byte = 0x20 + (random_byte(rng) % 0x5f);
        }
    }
    if size >= 20 + attr_len {
        for byte in &mut dst[20 + attr_len..] {
            *byte = random_byte(rng);
        }
    }
}

fn fill_sip(dst: &mut [u8], domain: Option<&str>, rng: &mut impl RngCore) {
    fill_random(dst, rng);
    if dst.len() < 31 {
        return;
    }

    static SEEDS: [(&str, &str, &str); 6] = [
        ("OPTIONS", "u", "x"),
        ("OPTIONS", "100", "pbx"),
        ("REGISTER", "101", "gw"),
        ("MESSAGE", "noc", "lan"),
        ("OPTIONS", "m", "voip"),
        ("REGISTER", "sip", "edge"),
    ];

    let seed = SEEDS[(rng.next_u32() as usize) % SEEDS.len()];
    if run_sip_candidate_chain(dst, seed, domain, true, rng) {
        return;
    }
    let _ = run_sip_candidate_chain(dst, seed, domain, false, rng);
}

fn run_sip_candidate_chain(
    dst: &mut [u8],
    seed: (&str, &str, &str),
    domain: Option<&str>,
    require_via: bool,
    rng: &mut impl RngCore,
) -> bool {
    if let Some(domain) = domain {
        if emit_sip(
            dst,
            seed.0,
            seed.1,
            &format!("{}.{}", seed.2, domain),
            require_via,
            rng,
        ) {
            return true;
        }
        if emit_sip(dst, seed.0, seed.1, domain, require_via, rng) {
            return true;
        }
        if emit_sip(
            dst,
            "OPTIONS",
            "u",
            &format!("x.{}", domain),
            require_via,
            rng,
        ) {
            return true;
        }
        if emit_sip(dst, "OPTIONS", "u", domain, require_via, rng) {
            return true;
        }
    }

    emit_sip(dst, seed.0, seed.1, seed.2, require_via, rng)
        || emit_sip(dst, "OPTIONS", "u", "x", require_via, rng)
}

fn emit_sip(
    dst: &mut [u8],
    method: &str,
    user: &str,
    host: &str,
    require_via: bool,
    rng: &mut impl RngCore,
) -> bool {
    let token = rng.next_u32();
    let mut pos = 0usize;

    if !put_sip_line(
        dst,
        &mut pos,
        &format!("{method} sip:{user}@{host} SIP/2.0\r\n"),
    ) {
        return false;
    }

    let via_ok = put_sip_line(
        dst,
        &mut pos,
        &format!("Via: SIP/2.0/UDP {host};branch=z9hG4bK{token:08x}\r\n"),
    );
    if require_via && !via_ok {
        return false;
    }

    if via_ok {
        let _ = put_sip_line(dst, &mut pos, "Max-Forwards: 70\r\n")
            && put_sip_line(
                dst,
                &mut pos,
                &format!("From: <sip:{user}@{host}>;tag={:04x}\r\n", token & 0xffff),
            )
            && put_sip_line(dst, &mut pos, &format!("To: <sip:{user}@{host}>\r\n"))
            && put_sip_line(dst, &mut pos, &format!("Call-ID: {token:08x}@{host}\r\n"))
            && put_sip_line(dst, &mut pos, &format!("CSeq: 1 {method}\r\n"));
    }

    dst[pos] = b'\r';
    dst[pos + 1] = b'\n';
    pos += 2;
    for byte in &mut dst[pos..] {
        *byte = b' ';
    }
    true
}

fn put_sip_line(dst: &mut [u8], pos: &mut usize, line: &str) -> bool {
    let add = line.len();
    if *pos + add + 2 > dst.len() {
        return false;
    }
    dst[*pos..*pos + add].copy_from_slice(line.as_bytes());
    *pos += add;
    true
}

fn fill_dns(dst: &mut [u8], trailing_size: usize, domain: Option<&str>, rng: &mut impl RngCore) {
    let size = dst.len();
    if size == 0 {
        return;
    }
    let total_len = size.saturating_add(trailing_size);

    if let Some(domain) = domain {
        let max_qname = size.saturating_sub(16);
        if let Some(name) = choose_dns_domain_qname(domain, max_qname, DNS_OPT_MIN_WIRE_SIZE, rng) {
            if emit_dns_domain(dst, total_len, &name, rng) {
                return;
            }
        }
    }

    if trailing_size > 0 && size >= 12 + 1 + 4 + DNS_OPT_MIN_WIRE_SIZE {
        let mut pos = write_dns_header(dst, rng);
        dst[pos] = 0x00;
        pos += 1;
        write_dns_question_tail(dst, &mut pos);
        if write_dns_opt_padding(dst, size, total_len, &mut pos, 10) {
            return;
        }
    }

    fill_dns_minimal_root_query(dst, rng);
}

fn emit_dns_domain(dst: &mut [u8], total_len: usize, name: &str, rng: &mut impl RngCore) -> bool {
    let qname_size = dns_qname_wire_size(name);
    if qname_size == 0 || dst.len() < 12 + qname_size + 4 + DNS_OPT_MIN_WIRE_SIZE {
        return false;
    }

    let mut pos = write_dns_header(dst, rng);
    if !write_dns_qname(dst, &mut pos, name) {
        return false;
    }
    write_dns_question_tail(dst, &mut pos);
    write_dns_opt_padding(dst, dst.len(), total_len, &mut pos, 10)
}

fn fill_dns_minimal_root_query(dst: &mut [u8], rng: &mut impl RngCore) {
    if dst.len() >= 2 {
        dst[0] = random_byte(rng);
        dst[1] = random_byte(rng);
    }
    if dst.len() >= 4 {
        // Flags 0x0120 (RD+AD): S-prefix DNS shaping matching wgbooster's
        // protocol-aware padding (Windows DNS Client); see write_dns_header.
        dst[2] = 0x01;
        dst[3] = 0x20;
    }
    if dst.len() >= 6 {
        dst[4] = 0x00;
        dst[5] = 0x01;
    }
    let header_tail_end = dst.len().min(12);
    if header_tail_end > 6 {
        for byte in &mut dst[6..header_tail_end] {
            *byte = 0x00;
        }
    }
    if dst.len() > 12 {
        dst[12] = 0x00;
    }
    if dst.len() > 13 {
        dst[13] = 0x00;
    }
    if dst.len() > 14 {
        dst[14] = 0x01;
    }
    if dst.len() > 15 {
        dst[15] = 0x00;
    }
    if dst.len() > 16 {
        dst[16] = 0x01;
    }
    if dst.len() > 17 {
        for byte in &mut dst[17..] {
            *byte = 0x00;
        }
    }
}

fn write_dns_header(dst: &mut [u8], rng: &mut impl RngCore) -> usize {
    dst[0] = random_byte(rng);
    dst[1] = random_byte(rng);
    // Flags 0x0120 (RD=1, AD=1): this is the S1-S4 prefix DNS shaping, which
    // faithfully matches wgbooster's `protocol_aware_padding_generator` (it sets
    // AD to mimic the Windows DNS Client). The standalone pre-handshake DNS
    // queries in `imitation::dns` deliberately use 0x0100 (RD only) instead, to
    // match wgbooster's live-query path (`simulate_browser_dns_resolution`).
    dst[2] = 0x01;
    dst[3] = 0x20;
    dst[4] = 0x00;
    dst[5] = 0x01;
    for byte in &mut dst[6..12] {
        *byte = 0x00;
    }
    12
}

fn write_dns_question_tail(dst: &mut [u8], pos: &mut usize) {
    dst[*pos] = 0x00;
    dst[*pos + 1] = 0x01;
    dst[*pos + 2] = 0x00;
    dst[*pos + 3] = 0x01;
    *pos += 4;
}

fn dns_qname_wire_size(name: &str) -> usize {
    if is_valid_imitation_host(name) {
        name.len() + 2
    } else {
        0
    }
}

fn write_dns_qname(dst: &mut [u8], pos: &mut usize, name: &str) -> bool {
    let wire_size = dns_qname_wire_size(name);
    if wire_size == 0 || *pos > dst.len() || wire_size > dst.len() - *pos {
        return false;
    }

    for label in name.split('.') {
        let label_len = label.len();
        if label_len == 0 || label_len > 63 || *pos + 1 + label_len > dst.len() {
            return false;
        }
        dst[*pos] = label_len as u8;
        *pos += 1;
        dst[*pos..*pos + label_len].copy_from_slice(label.as_bytes());
        *pos += label_len;
    }
    if *pos >= dst.len() {
        return false;
    }
    dst[*pos] = 0x00;
    *pos += 1;
    true
}

fn choose_dns_domain_qname(
    domain: &str,
    max_wire_size: usize,
    opt_reserve: usize,
    rng: &mut impl RngCore,
) -> Option<String> {
    if !is_valid_imitation_host(domain) {
        return None;
    }

    const PREFIXES: [&str; 5] = ["www", "api", "cdn", "dns", ""];
    let start = (rng.next_u32() as usize) % PREFIXES.len();
    let budgets = [
        if opt_reserve > 0 && opt_reserve <= max_wire_size {
            max_wire_size - opt_reserve
        } else {
            0
        },
        max_wire_size,
    ];

    for budget in budgets {
        if budget == 0 {
            continue;
        }
        for i in 0..PREFIXES.len() {
            let prefix = PREFIXES[(start + i) % PREFIXES.len()];
            let candidate = if prefix.is_empty() {
                domain.to_owned()
            } else {
                format!("{prefix}.{domain}")
            };
            let wire_size = dns_qname_wire_size(&candidate);
            if wire_size > 0 && wire_size <= budget {
                return Some(candidate);
            }
        }
    }

    None
}

fn write_dns_opt_padding(
    dst: &mut [u8],
    write_limit: usize,
    total_len: usize,
    pos: &mut usize,
    arcount_pos: usize,
) -> bool {
    if total_len < write_limit {
        return false;
    }
    if *pos > write_limit || write_limit - *pos < DNS_OPT_MIN_WIRE_SIZE {
        return false;
    }
    if arcount_pos >= write_limit.saturating_sub(1) {
        return false;
    }
    if total_len - *pos - DNS_OPT_FIXED_LEN > 0xffff {
        return false;
    }

    let option_code = if total_len > write_limit {
        0xfde9u16
    } else {
        0x000cu16
    };

    // EDNS(0) OPT pseudo-record: root NAME (0x00), TYPE=OPT (0x0029),
    // CLASS=requestor UDP payload size (0x1000), TTL=0 (extended RCODE/flags).
    dst[*pos] = 0x00;
    dst[*pos + 1] = 0x00;
    dst[*pos + 2] = 0x29;
    dst[*pos + 3] = 0x10;
    dst[*pos + 4] = 0x00;
    dst[*pos + 5] = 0x00;
    dst[*pos + 6] = 0x00;
    dst[*pos + 7] = 0x00;
    dst[*pos + 8] = 0x00;
    *pos += 9;

    let rdata_len = total_len - *pos - 2;
    dst[*pos] = ((rdata_len >> 8) & 0xff) as u8;
    dst[*pos + 1] = (rdata_len & 0xff) as u8;
    *pos += 2;

    let pad_value_len = rdata_len - 4;
    dst[*pos] = (option_code >> 8) as u8;
    dst[*pos + 1] = option_code as u8;
    dst[*pos + 2] = ((pad_value_len >> 8) & 0xff) as u8;
    dst[*pos + 3] = (pad_value_len & 0xff) as u8;
    *pos += 4;

    while *pos < write_limit {
        dst[*pos] = 0x00;
        *pos += 1;
    }

    dst[arcount_pos] = 0x00;
    dst[arcount_pos + 1] = 0x01;
    true
}

/// Permissive validation for a QUIC ClientHello SNI: unlike DNS QNAMEs and SIP
/// URIs, the SNI is a length-prefixed TLS extension, so UTF-8/IDN host names are
/// accepted (matching wgbooster). Only emptiness, the 253-byte RFC 1035 bound,
/// and control bytes (which never appear in a real SNI) are rejected.
fn is_valid_quic_sni(host: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && !host.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn is_valid_imitation_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.starts_with('-')
        || host.ends_with('.')
        || host.ends_with('-')
    {
        return false;
    }

    let mut label_len = 0usize;
    let mut label_start = true;
    let mut previous_hyphen = false;

    for byte in host.bytes() {
        if byte == b'.' {
            if label_len == 0 || previous_hyphen {
                return false;
            }
            label_len = 0;
            label_start = true;
            previous_hyphen = false;
            continue;
        }

        if !(byte.is_ascii_alphanumeric() || byte == b'-') {
            return false;
        }
        if label_start && byte == b'-' {
            return false;
        }

        label_len += 1;
        if label_len > 63 {
            return false;
        }
        label_start = false;
        previous_hyphen = byte == b'-';
    }

    label_len > 0 && !previous_hyphen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{COOKIE_REPLY, DATA, HANDSHAKE_INIT, HANDSHAKE_RESP};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    fn write_tag(packet: &mut [u8], tag: u32) {
        packet[..4].copy_from_slice(&tag.to_le_bytes());
    }

    fn packet_after_prepend(
        cfg: &AmneziaConfig,
        packet_size: usize,
        tag: u32,
        capacity: usize,
    ) -> Vec<u8> {
        let obf = ObfuscationRanges::default();
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut buffer = vec![0u8; capacity];
        write_tag(&mut buffer, tag);
        buffer[4] = 0x42;

        cfg.prepend_outbound(obf, &mut buffer, packet_size, &mut rng)
            .unwrap()
            .to_vec()
    }

    fn expected_junk(cfg: &AmneziaConfig, tag: u32) -> usize {
        let size = match tag {
            HANDSHAKE_INIT => cfg.init_packet_junk_size,
            HANDSHAKE_RESP => cfg.response_packet_junk_size,
            COOKIE_REPLY => cfg.cookie_packet_junk_size,
            DATA => cfg.transport_packet_junk_size,
            _ => unreachable!(),
        };
        size as usize
    }

    /// For every packet kind, S-size combination, and imitation protocol, a
    /// packet that is prefixed by `prepend_outbound` must be recovered exactly
    /// by `strip_inbound`. This is the core invariant the wire protocol relies
    /// on, and it exercises every protocol-shaped filler against the stripper.
    #[test]
    fn prepend_then_strip_roundtrips_across_configs_and_protocols() {
        use AmneziaImitationProtocol::*;

        let obf = ObfuscationRanges::default();
        let kinds: [(u32, usize); 4] = [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 48),
        ];
        let bases = [
            AmneziaConfig::new(7, 11, 13, 17),
            AmneziaConfig::new(1, 1, 1, 1),
            AmneziaConfig::new(64, 0, 0, 200),
        ];

        for base in bases {
            for protocol in [None, Dns, Quic, Sip, Stun] {
                let cfg = base
                    .clone()
                    .with_protocol_imitation(protocol, Some("example.com".to_owned()));
                let mut rng = ChaCha8Rng::seed_from_u64(0xA53);

                for &(tag, base_size) in &kinds {
                    let mut original = vec![0u8; base_size];
                    write_tag(&mut original, tag);
                    for (i, byte) in original[4..].iter_mut().enumerate() {
                        *byte = (i as u8) ^ 0x5a;
                    }

                    let mut buffer = vec![0u8; base_size + 1280];
                    buffer[..base_size].copy_from_slice(&original);
                    let padded = cfg
                        .prepend_outbound(obf, &mut buffer, base_size, &mut rng)
                        .unwrap()
                        .to_vec();

                    let junk = expected_junk(&cfg, tag);
                    assert_eq!(
                        padded.len(),
                        base_size + junk,
                        "unexpected padded size: protocol={protocol:?} tag={tag} junk={junk}"
                    );

                    // Every shape produced by prepend_outbound must be accepted:
                    // this is the property that makes the stricter filter safe.
                    let stripped = cfg.strip_inbound(obf, &padded);
                    assert_eq!(
                        stripped,
                        Some(original.as_slice()),
                        "roundtrip mismatch: protocol={protocol:?} tag={tag} junk={junk}"
                    );
                }
            }
        }
    }

    /// What our own outbound cover traffic looks like to the probe detector.
    ///
    /// This table is the reason a server must classify AmneziaWG *before* it
    /// considers answering a probe. Three properties, all observed rather than
    /// assumed -- the verdicts were printed first and locked in afterwards:
    ///
    /// 1. **No cross-protocol confusion.** Across every protocol x packet kind
    ///    x S-size combination, the verdict is either `None` or the protocol we
    ///    configured. Our DNS cover traffic is never mistaken for STUN, and so
    ///    on. This is the safety property and it holds unconditionally.
    ///
    /// 2. **DNS and SIP cover traffic is detected as a probe.** At realistic S
    ///    sizes -- the installer rolls S1-S4 in 15..150 -- a datagram we emit
    ///    under `ip=dns` is a well-formed DNS query, because `fill_dns` frames
    ///    the WireGuard ciphertext inside an EDNS OPT padding option. A server
    ///    that asked "is this a probe?" first would answer its own clients
    ///    instead of handshaking with them, and would do so *more* often the
    ///    better the imitation became.
    ///
    /// 3. **QUIC and STUN are never self-detected**, and both are structural
    ///    rather than incidental:
    ///    - `fill_quic_short` writes a 1-RTT short header, so the leading two
    ///      bits are `0b01` and the long-header test cannot fire.
    ///    - `fill_stun` frames `msg_len` over the junk region only, while the
    ///      datagram continues with the WireGuard packet, so the detector's
    ///      `len == 20 + msg_len` check fails.
    ///
    ///    Both are worth pinning: this test fails the day someone extends
    ///    `fill_stun` to frame the whole datagram, or reverts S2/S3 to a QUIC
    ///    long header -- changes that would look like fidelity improvements
    ///    while silently making the server answer its own peers.
    #[test]
    fn our_cover_traffic_is_detected_as_the_protocol_we_imitate() {
        use crate::noise::imitation::detect::{detect, Probe};
        use AmneziaImitationProtocol::*;

        let obf = ObfuscationRanges::default();
        let kinds: [(u32, usize); 4] = [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 48),
        ];
        // The last entry mirrors what `amneziawg-install` actually generates.
        let bases = [
            AmneziaConfig::new(7, 11, 13, 17),
            AmneziaConfig::new(1, 1, 1, 1),
            AmneziaConfig::new(64, 0, 0, 200),
            AmneziaConfig::new(120, 130, 110, 80),
        ];

        let mut self_detected = 0usize;

        for base in &bases {
            for protocol in [None, Dns, Quic, Sip, Stun] {
                let cfg = base
                    .clone()
                    .with_protocol_imitation(protocol, Some("example.com".to_owned()));
                let mut rng = ChaCha8Rng::seed_from_u64(0xA53);

                for &(tag, base_size) in &kinds {
                    let mut buffer = vec![0u8; base_size + 1280];
                    write_tag(&mut buffer, tag);
                    let padded = cfg
                        .prepend_outbound(obf, &mut buffer, base_size, &mut rng)
                        .unwrap()
                        .to_vec();
                    let junk = expected_junk(&cfg, tag);
                    let verdict = detect(&padded);

                    // Checked before the generic cross-protocol assertion
                    // below, which would otherwise fire first here and report
                    // "cover traffic for None detected as Dns" -- true, but a
                    // worse description of the failure than this one. Random
                    // junk resembling any probe means the detector is too
                    // loose, and that is what a reader needs told.
                    if protocol == None {
                        assert!(
                            verdict.is_none(),
                            "random junk was detected as {:?} (junk={}, tag={})",
                            verdict,
                            junk,
                            tag
                        );
                    }

                    // (1) never a *different* protocol.
                    if let Some(p) = verdict {
                        assert!(
                            p.is(protocol),
                            "cover traffic for {:?} detected as {:?} (junk={}, tag={})",
                            protocol,
                            p,
                            junk,
                            tag
                        );
                        self_detected += 1;
                    }

                    // (3) QUIC and STUN never frame the whole datagram.
                    if matches!(protocol, Quic | Stun) {
                        assert!(
                            verdict.is_none(),
                            "{:?} imitation became self-detecting (junk={}, tag={}); see this test's doc comment before changing it",
                            protocol,
                            junk,
                            tag
                        );
                    }
                }
            }
        }

        // (2) the hazard is real, not hypothetical: at installer-realistic S
        // sizes every DNS and SIP datagram we emit is a valid probe. Asserted
        // as a count so the test fails if imitation quietly stops working, not
        // only if it starts misfiring.
        let realistic = AmneziaConfig::new(120, 130, 110, 80);
        for protocol in [Dns, Sip] {
            let cfg = realistic
                .clone()
                .with_protocol_imitation(protocol, Some("example.com".to_owned()));
            let mut rng = ChaCha8Rng::seed_from_u64(0xA53);
            for &(tag, base_size) in &kinds {
                let mut buffer = vec![0u8; base_size + 1280];
                write_tag(&mut buffer, tag);
                let padded = cfg
                    .prepend_outbound(obf, &mut buffer, base_size, &mut rng)
                    .unwrap()
                    .to_vec();
                let verdict = detect(&padded);
                assert!(
                    verdict.is_some_and(|p| p.is(protocol)),
                    "{:?} cover traffic at realistic S sizes must be self-detecting, got {:?} (tag={})",
                    protocol,
                    verdict,
                    tag
                );
            }
        }

        // Actual is 13 across the four S configurations. The bound guards
        // against imitation regressing toward zero, so it sits well below that
        // rather than one step under it -- a threshold of 12 would fail on any
        // legitimate change that drops a single combination.
        assert!(
            self_detected >= 8,
            "expected our cover traffic to be probe-shaped in many cases, saw only {}; if imitation regressed this is where it shows",
            self_detected
        );
        let _: fn(&[u8]) -> Option<Probe> = detect;
    }

    /// The full input matrix for `strip_inbound`, written before the change
    /// that made it fallible rather than after. The risk of that change is
    /// dropping *valid* traffic, so every configuration shape is enumerated:
    /// all-zero (plain WireGuard), fully padded, and mixed.
    #[test]
    fn strip_inbound_accepts_every_conforming_shape_and_rejects_the_rest() {
        let obf = ObfuscationRanges::default();

        // --- all S zero: must behave exactly like plain WireGuard ---------
        let vanilla = AmneziaConfig::new(0, 0, 0, 0);
        for (tag, size) in [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 48),
        ] {
            let mut p = vec![0xaa; size];
            write_tag(&mut p, tag);
            assert_eq!(
                vanilla.strip_inbound(obf, &p).map(|d| d.len()),
                Some(size),
                "vanilla must accept tag {:#x} unchanged",
                tag
            );
        }
        // Too short to be anything, and a tag that matches no range.
        assert_eq!(vanilla.strip_inbound(obf, &[0u8; 10]), None);
        let mut bogus = vec![0xaa; HANDSHAKE_INIT_SZ];
        write_tag(&mut bogus, 0x5555_5555);
        assert_eq!(vanilla.strip_inbound(obf, &bogus), None, "unknown tag");

        // --- every S configured -------------------------------------------
        let padded = AmneziaConfig::new(120, 130, 110, 80);
        for (tag, size, junk) in [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ, 120usize),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ, 130),
            (COOKIE_REPLY, COOKIE_REPLY_SZ, 110),
            (DATA, DATA_OVERHEAD_SZ + 48, 80),
        ] {
            let mut p = vec![0xaa; junk + size];
            write_tag(&mut p[junk..], tag);
            assert_eq!(
                padded.strip_inbound(obf, &p).map(|d| d.len()),
                Some(size),
                "padded tag {:#x} must strip to its base size",
                tag
            );

            // The same packet *unpadded* is not ours and must be rejected.
            let mut bare = vec![0xaa; size];
            write_tag(&mut bare, tag);
            assert_eq!(
                padded.strip_inbound(obf, &bare),
                None,
                "unpadded tag {:#x} must be dropped when its S is configured",
                tag
            );
        }

        // --- mixed: S1 set, S4 zero ----------------------------------------
        let mixed = AmneziaConfig::new(15, 0, 0, 0);
        let mut init = vec![0xaa; 15 + HANDSHAKE_INIT_SZ];
        write_tag(&mut init[15..], HANDSHAKE_INIT);
        assert_eq!(
            mixed.strip_inbound(obf, &init).map(|d| d.len()),
            Some(HANDSHAKE_INIT_SZ)
        );
        // S4 = 0, so unpadded transport is still the conforming shape and must
        // keep working. This is the case a naive 'reject anything unpadded'
        // would break.
        let mut data = vec![0xaa; DATA_OVERHEAD_SZ + 16];
        write_tag(&mut data, DATA);
        assert_eq!(
            mixed.strip_inbound(obf, &data).map(|d| d.len()),
            Some(DATA_OVERHEAD_SZ + 16),
            "S4 = 0 means unpadded transport is conforming"
        );
        // But an unpadded init is not, because S1 is set.
        let mut bare_init = vec![0xaa; HANDSHAKE_INIT_SZ];
        write_tag(&mut bare_init, HANDSHAKE_INIT);
        assert_eq!(mixed.strip_inbound(obf, &bare_init), None);
    }

    #[test]
    fn strips_inbound_s1_to_s4_when_magic_matches() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(7, 11, 13, 17);

        let mut init = vec![0xaa; cfg.init_packet_junk_size as usize + HANDSHAKE_INIT_SZ];
        write_tag(
            &mut init[cfg.init_packet_junk_size as usize..],
            HANDSHAKE_INIT,
        );
        assert_eq!(
            cfg.strip_inbound(obf, &init).map(|d| d.len()),
            Some(HANDSHAKE_INIT_SZ)
        );

        let mut resp = vec![0xaa; cfg.response_packet_junk_size as usize + HANDSHAKE_RESP_SZ];
        write_tag(
            &mut resp[cfg.response_packet_junk_size as usize..],
            HANDSHAKE_RESP,
        );
        assert_eq!(
            cfg.strip_inbound(obf, &resp).map(|d| d.len()),
            Some(HANDSHAKE_RESP_SZ)
        );

        let mut cookie = vec![0xaa; cfg.cookie_packet_junk_size as usize + COOKIE_REPLY_SZ];
        write_tag(
            &mut cookie[cfg.cookie_packet_junk_size as usize..],
            COOKIE_REPLY,
        );
        assert_eq!(
            cfg.strip_inbound(obf, &cookie).map(|d| d.len()),
            Some(COOKIE_REPLY_SZ)
        );

        let mut data = vec![0xaa; cfg.transport_packet_junk_size as usize + DATA_OVERHEAD_SZ + 8];
        write_tag(&mut data[cfg.transport_packet_junk_size as usize..], DATA);
        assert_eq!(
            cfg.strip_inbound(obf, &data).map(|d| d.len()),
            Some(DATA_OVERHEAD_SZ + 8)
        );
    }

    #[test]
    fn rejects_inbound_packet_whose_magic_does_not_match_its_shape() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(7, 11, 13, 17);
        let mut resp = vec![0xaa; cfg.response_packet_junk_size as usize + HANDSHAKE_RESP_SZ];
        write_tag(&mut resp[cfg.response_packet_junk_size as usize..], DATA);

        // The size says handshake response, the tag says transport data: it
        // matches no configured shape. Previously this was handed back for
        // the caller to reject; rejecting it here is the same outcome reached
        // one layer earlier, and without a second chance to be misread.
        assert_eq!(cfg.strip_inbound(obf, &resp), None);
    }

    #[test]
    fn rejects_unpadded_transport_when_s4_is_configured() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(0, 0, 0, 17);
        let mut data = vec![0xaa; DATA_OVERHEAD_SZ + 32];
        write_tag(&mut data, DATA);

        // S4 is configured, so a conforming peer always pads. Handing this
        // back would let the caller re-read the tag at offset 0 and accept
        // it, which is the filtering gap this rejection closes.
        assert_eq!(cfg.strip_inbound(obf, &data), None);
    }

    #[test]
    fn strips_padded_transport_when_junk_prefix_also_looks_like_h4() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(0, 0, 0, 17);
        let junk_size = cfg.transport_packet_junk_size as usize;
        let mut data = vec![0xaa; junk_size + DATA_OVERHEAD_SZ + 32];

        write_tag(&mut data, DATA);
        write_tag(&mut data[junk_size..], DATA);
        data[junk_size + 4] = 0x42;

        let stripped = cfg.strip_inbound(obf, &data);

        assert_eq!(stripped, Some(&data[junk_size..]));
    }

    #[test]
    fn prepends_outbound_junk_for_matching_packet_type() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(7, 11, 13, 17);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut buffer = vec![0u8; HANDSHAKE_INIT_SZ + 64];
        write_tag(&mut buffer, HANDSHAKE_INIT);
        buffer[4] = 0x42;

        let packet = cfg
            .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, &mut rng)
            .unwrap();

        assert_eq!(packet.len(), HANDSHAKE_INIT_SZ + 7);
        assert_eq!(&packet[7..11], &HANDSHAKE_INIT.to_le_bytes());
        assert_eq!(packet[11], 0x42);
    }

    #[test]
    fn validate_accepts_sizes_that_fit_and_rejects_those_that_cannot() {
        // Junk + base packet must fit in one sendable UDP datagram
        // (MAX_SENDABLE_DATAGRAM = 65507, the IPv4 payload limit) -- not the
        // 65535 protocol ceiling the kernel module bounds by.
        assert!(AmneziaConfig::new(0, 0, 0, 0).validate().is_ok());
        assert!(AmneziaConfig::new(1000, 1000, 1000, 1000)
            .validate()
            .is_ok());

        // Exactly at the limit for each packet type.
        let max_s1 = (MAX_SENDABLE_DATAGRAM - HANDSHAKE_INIT_SZ) as u16;
        let max_s2 = (MAX_SENDABLE_DATAGRAM - HANDSHAKE_RESP_SZ) as u16;
        let max_s3 = (MAX_SENDABLE_DATAGRAM - COOKIE_REPLY_SZ) as u16;
        let max_s4 = (MAX_SENDABLE_DATAGRAM - DATA_OVERHEAD_SZ) as u16;
        assert!(AmneziaConfig::new(max_s1, max_s2, max_s3, max_s4)
            .validate()
            .is_ok());

        // One byte over, each in turn.
        for (cfg, want) in [
            (AmneziaConfig::new(max_s1 + 1, 0, 0, 0), "S1"),
            (AmneziaConfig::new(0, max_s2 + 1, 0, 0), "S2"),
            (AmneziaConfig::new(0, 0, max_s3 + 1, 0), "S3"),
            (AmneziaConfig::new(0, 0, 0, max_s4 + 1), "S4"),
        ] {
            let err = cfg.validate().expect_err("must be rejected");
            assert!(err.contains(want), "error should name {}: {}", want, err);
        }
    }

    #[test]
    fn validate_rejects_sizes_that_fit_the_protocol_but_not_a_udp_datagram() {
        // The protocol ceiling is 65535, but an IPv4 UDP payload tops out at
        // 65535 - 20 - 8 = 65507. Sizes in between pass the kernel module's
        // check and then fail at send time with EMSGSIZE, so they must be
        // rejected here rather than accepted into a tunnel that never works.
        const PROTOCOL_MAX: usize = 65535;
        assert_eq!(MAX_SENDABLE_DATAGRAM, 65507);

        // For each field: the size the protocol ceiling alone would allow.
        let cases = [
            ("S1", HANDSHAKE_INIT_SZ, 0usize),
            ("S2", HANDSHAKE_RESP_SZ, 1),
            ("S3", COOKIE_REPLY_SZ, 2),
            ("S4", DATA_OVERHEAD_SZ, 3),
        ];

        for (label, base, slot) in cases {
            let over = (PROTOCOL_MAX - base) as u16;
            let mut s = [0u16; 4];
            s[slot] = over;
            let cfg = AmneziaConfig::new(s[0], s[1], s[2], s[3]);

            let err = cfg.validate().expect_err(&format!(
                "{}={} yields a {}-byte datagram, unsendable over IPv4",
                label,
                over,
                over as usize + base
            ));
            assert!(err.contains(label), "error should name {}: {}", label, err);
        }
    }

    #[test]
    fn validated_max_size_actually_round_trips_through_prepend_outbound() {
        // The bound is only meaningful if the largest accepted configuration can
        // still emit a packet -- otherwise validate() would be off by one.
        let obf = ObfuscationRanges::default();
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let max_s1 = (MAX_SENDABLE_DATAGRAM - HANDSHAKE_INIT_SZ) as u16;
        let cfg = AmneziaConfig::new(max_s1, 0, 0, 0);
        cfg.validate().unwrap();

        let mut buffer = vec![0u8; MAX_SENDABLE_DATAGRAM];
        write_tag(&mut buffer, HANDSHAKE_INIT);

        let packet = cfg
            .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, &mut rng)
            .expect("largest validated S1 must still fit");
        assert_eq!(packet.len(), MAX_SENDABLE_DATAGRAM);
    }

    /// [`AmneziaConfig::cookie_reply_len`] must agree with the length
    /// `prepend_outbound` actually produces, for every S3 from zero to the
    /// largest `validate` admits.
    ///
    /// The ingress path predicts the length so it can refuse an amplifying
    /// cookie reply *without* paying to generate its junk. A prediction that
    /// ran low would let the amplifier through; one that ran high would silence
    /// cookie replies for a configuration that is not an amplifier at all. Both
    /// are silent, so the two are pinned to each other here rather than left to
    /// agree by inspection.
    #[test]
    fn the_predicted_cookie_reply_length_is_the_one_actually_produced() {
        let max_s3 = (MAX_SENDABLE_DATAGRAM - COOKIE_REPLY_SZ) as u16;
        for s3 in [0u16, 1, 110, 1280, max_s3] {
            let cfg = AmneziaConfig::new(0, 0, s3, 0);
            cfg.validate().expect("S3 within the validated range");

            let produced = packet_after_prepend(
                &cfg,
                COOKIE_REPLY_SZ,
                COOKIE_REPLY,
                COOKIE_REPLY_SZ + s3 as usize,
            )
            .len();

            assert_eq!(
                cfg.cookie_reply_len(COOKIE_REPLY_SZ),
                produced,
                "S3 = {}: predicted length must match the datagram prepend_outbound emits",
                s3
            );
        }
    }

    #[test]
    fn quic_imitation_uses_short_header_for_every_packet_kind() {
        let cfg = AmneziaConfig::new(8, 9, 10, 11)
            .with_protocol_imitation(AmneziaImitationProtocol::Quic, None);

        // Every S-region is a 1-RTT short header: form bit clear, fixed bit
        // set. A long header would carry a length field that cannot frame the
        // WireGuard packet that follows, and S2/S3 are far below the 1200-byte
        // minimum a valid Initial requires (RFC 9000 §14.1).
        let cases = [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 4),
        ];

        for (tag, packet_size) in cases {
            let junk_size = expected_junk(&cfg, tag);
            let packet = packet_after_prepend(&cfg, packet_size, tag, packet_size + 64);

            assert_eq!(
                packet[0] & 0xc0,
                0x40,
                "tag={:#x} must use a 1-RTT short header, got first byte {:#04x}",
                tag,
                packet[0]
            );
            assert_eq!(
                &packet[junk_size..junk_size + 4],
                &tag.to_le_bytes(),
                "tag={:#x} payload must start right after the junk prefix",
                tag
            );
        }
    }

    #[test]
    fn quic_pre_handshake_junk_keeps_long_header_initial_at_rfc_minimum_size() {
        // The Jc path is the one place a long-header Initial is legal: it is a
        // standalone client->server datagram and its size is drawn from
        // QUIC_JUNK_SIZE_MIN..=MAX, which starts at the RFC 9000 §14.1 minimum.
        // Deliberately an independent literal rather than QUIC_JUNK_SIZE_MIN:
        // this is an external requirement imposed by the RFC, and the point of
        // the test is that our constant satisfies it. Asserting against
        // QUIC_JUNK_SIZE_MIN would be tautological, since the junk length is
        // drawn from that very constant.
        const RFC9000_MIN_INITIAL_DATAGRAM: usize = 1200;
        assert!(
            QUIC_JUNK_SIZE_MIN >= RFC9000_MIN_INITIAL_DATAGRAM,
            "QUIC_JUNK_SIZE_MIN ({}) must not drop below the RFC 9000 §14.1 \
             minimum ({}), or the Jc path emits invalid Initials",
            QUIC_JUNK_SIZE_MIN,
            RFC9000_MIN_INITIAL_DATAGRAM
        );

        let cfg = AmneziaConfig::new(0, 0, 0, 0)
            .with_pre_handshake_junk(1, 0, 0, 0)
            .with_protocol_imitation(AmneziaImitationProtocol::Quic, None);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut buffer = vec![0u8; QUIC_JUNK_SIZE_MAX];

        let junk = cfg.fill_pre_handshake_junk(&mut buffer, &mut rng).unwrap();

        assert!(
            junk.len() >= RFC9000_MIN_INITIAL_DATAGRAM,
            "a long-header Initial needs a >={} byte datagram, got {}",
            RFC9000_MIN_INITIAL_DATAGRAM,
            junk.len()
        );
        assert_eq!(junk[0] & 0xc0, 0xc0, "long header form + fixed bit");
        assert_eq!(&junk[1..5], &[0x00, 0x00, 0x00, 0x01], "QUIC v1");
    }

    #[test]
    fn dns_imitation_wraps_trailing_wireguard_payload_in_opt_record() {
        let cfg = AmneziaConfig::new(0, 0, 0, 64).with_protocol_imitation(
            AmneziaImitationProtocol::Dns,
            Some("example.com".to_owned()),
        );

        let packet = packet_after_prepend(&cfg, DATA_OVERHEAD_SZ + 8, DATA, DATA_OVERHEAD_SZ + 128);
        let prefix = &packet[..64];
        assert_eq!(&prefix[10..12], &[0x00, 0x01]);

        let mut pos = 12usize;
        while prefix[pos] != 0 {
            pos += 1 + prefix[pos] as usize;
        }
        pos += 1 + 4;
        assert_eq!(prefix[pos], 0x00);
        assert_eq!(&prefix[pos + 1..pos + 3], &[0x00, 0x29]);

        let rdlen = u16::from_be_bytes([prefix[pos + 9], prefix[pos + 10]]) as usize;
        assert_eq!(rdlen, packet.len() - pos - DNS_OPT_FIXED_LEN);
    }

    #[test]
    fn sip_imitation_reuses_valid_configured_domain_when_it_fits() {
        let cfg = AmneziaConfig::new(96, 0, 0, 0).with_protocol_imitation(
            AmneziaImitationProtocol::Sip,
            Some("example.com".to_owned()),
        );

        let packet = packet_after_prepend(
            &cfg,
            HANDSHAKE_INIT_SZ,
            HANDSHAKE_INIT,
            HANDSHAKE_INIT_SZ + 128,
        );
        let prefix = std::str::from_utf8(&packet[..96]).unwrap();
        assert!(
            prefix.starts_with("OPTIONS")
                || prefix.starts_with("REGISTER")
                || prefix.starts_with("MESSAGE")
        );
        assert!(prefix.contains("sip:"));
        assert!(prefix.contains("example.com"));
    }

    #[test]
    fn stun_imitation_emits_binding_request_prefix() {
        let cfg = AmneziaConfig::new(0, 0, 0, 40)
            .with_protocol_imitation(AmneziaImitationProtocol::Stun, None);

        let packet = packet_after_prepend(&cfg, DATA_OVERHEAD_SZ + 4, DATA, DATA_OVERHEAD_SZ + 64);
        let prefix = &packet[..40];
        assert_eq!(&prefix[..2], &[0x00, 0x01]);
        assert_eq!(&prefix[4..8], &[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(u16::from_be_bytes([prefix[2], prefix[3]]) % 4, 0);
    }

    #[test]
    fn pre_handshake_junk_allows_fixed_packet_size() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_pre_handshake_junk(1, 42, 42, 0);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut buffer = vec![0u8; 128];

        let packet = cfg.fill_pre_handshake_junk(&mut buffer, &mut rng).unwrap();

        assert_eq!(packet.len(), 42);
    }

    #[test]
    fn quic_sni_accepts_utf8_idn_while_dns_sip_require_ldh() {
        // QUIC SNI is a length-prefixed TLS extension: UTF-8/IDN accepted.
        assert!(is_valid_quic_sni("xn--nxasmq6b.com"));
        assert!(is_valid_quic_sni("пример.рф"));
        assert!(!is_valid_quic_sni(""));
        assert!(!is_valid_quic_sni("bad\r\nhost"));
        assert!(!is_valid_quic_sni(&"a".repeat(254)));

        // A non-ASCII domain is kept for QUIC but dropped for DNS/SIP (strict).
        let quic = AmneziaImitation::new(
            AmneziaImitationProtocol::Quic,
            Some("пример.рф".to_owned()),
            AmneziaImitationBrowser::Default,
        );
        assert_eq!(quic.domain(), Some("пример.рф"));
        let dns = AmneziaImitation::new(
            AmneziaImitationProtocol::Dns,
            Some("пример.рф".to_owned()),
            AmneziaImitationBrowser::Default,
        );
        assert_eq!(dns.domain(), None);
    }

    #[test]
    fn quic_default_browser_emits_single_curl_initial() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_protocol_imitation(
            AmneziaImitationProtocol::Quic,
            Some("example.com".to_owned()),
        );
        assert!(cfg.has_imitation_sequence());

        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let seq = cfg.pre_handshake_imitation_datagrams(&mut rng);
        // Omitted browser -> curl -> one Initial, back-to-back (zero delay).
        assert_eq!(seq.len(), 1);
        assert_eq!(seq[0].0, Duration::from_millis(0));
        assert_eq!(seq[0].1.len(), 1250);
    }

    #[test]
    fn pre_handshake_junk_rejects_zero_min_packet_size() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_pre_handshake_junk(1, 0, 10, 0);

        assert_eq!(
            cfg.pre_handshake_junk.packet_size_min,
            DEFAULT_JUNK_PACKET_SIZE_MIN
        );
        assert_eq!(
            cfg.pre_handshake_junk.packet_size_max,
            DEFAULT_JUNK_PACKET_SIZE_MAX
        );
    }

    #[test]
    fn protocol_imitation_fillers_tolerate_tiny_buffers() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for size in 0..32 {
            let mut stun = vec![0u8; size];
            fill_stun(&mut stun, &mut rng);

            let mut dns = vec![0u8; size];
            fill_dns_minimal_root_query(&mut dns, &mut rng);
        }
    }

    /// `cookie_reply_amplifies` agrees with the rule `reply_policy` enforces,
    /// on both packet kinds and at the boundary.
    ///
    /// The two live in different modules and neither can see the other, so the
    /// only thing keeping them in step is this test. The response bound
    /// (`S3 > S2 + 28`) is the tighter of the two and had no coverage at all.
    #[test]
    fn cookie_reply_amplifies_agrees_with_the_rule_that_suppresses() {
        // Parity exactly: 64 + S3 == 148 + S1 and == 92 + S2. Not an amplifier.
        let ok = AmneziaConfig::new(100, 156, 184, 0);
        assert_eq!(
            ok.cookie_reply_amplifies(),
            None,
            "parity is not amplifying"
        );

        // One byte over on the initiation side.
        let over_s1 = AmneziaConfig::new(100, 156, 185, 0);
        assert_eq!(
            over_s1.cookie_reply_amplifies(),
            Some(("S1", 248, 249)),
            "one byte past the initiation bound must be reported"
        );

        // The response bound is tighter, so a config can clear S1 and fail S2.
        let over_s2 = AmneziaConfig::new(200, 100, 250, 0);
        assert_eq!(
            over_s2.cookie_reply_amplifies(),
            Some(("S2", 192, 314)),
            "the response bound is the tighter one and must be checked too"
        );

        // The shape a real installer rolls: S1 small, S3 large.
        let installer = AmneziaConfig::new(15, 15, 150, 0);
        assert!(
            installer.cookie_reply_amplifies().is_some(),
            "S1=15 S3=150 is a shape independent rolls produce, and it amplifies"
        );

        // And the interop harness's own sizes must not trip it.
        let harness = AmneziaConfig::new(120, 130, 110, 80);
        assert_eq!(
            harness.cookie_reply_amplifies(),
            None,
            "the sizes scripts/awg-interop-poc.sh runs must keep their cookies"
        );
    }
}
