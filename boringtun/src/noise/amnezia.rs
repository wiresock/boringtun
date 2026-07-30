// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

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
const DNS_JUNK_SIZE_MIN: usize = 50;
const DNS_JUNK_SIZE_MAX: usize = 200;
const QUIC_JUNK_SIZE_MIN: usize = 1200;
const QUIC_JUNK_SIZE_MAX: usize = 1252;
const SIP_JUNK_SIZE_MIN: usize = 200;
const SIP_JUNK_SIZE_MAX: usize = 1200;
const STUN_JUNK_SIZE_MIN: usize = 28;
const STUN_JUNK_SIZE_MAX: usize = 100;
/// RFC 5389 STUN magic cookie, present at bytes 4..8 of every STUN message.
const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

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

    fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmneziaConfig {
    pub(crate) init_packet_junk_size: u16,
    pub(crate) response_packet_junk_size: u16,
    pub(crate) cookie_packet_junk_size: u16,
    pub(crate) transport_packet_junk_size: u16,
    pub(crate) pre_handshake_junk: AmneziaPreHandshakeJunk,
    pub(crate) imitation: AmneziaImitation,
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

    /// True when a full protocol-natural imitation sequence should be emitted
    /// for the pre-handshake phase. DNS/SIP/STUN/QUIC all qualify (QUIC's omitted
    /// browser defaults to curl, matching wgbooster); only `None` does not.
    pub(crate) fn has_imitation_sequence(&self) -> bool {
        self.imitation.protocol != AmneziaImitationProtocol::None
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

    pub fn strip_inbound<'a>(&self, obf: ObfuscationRanges, packet: &'a [u8]) -> &'a [u8] {
        if self.inbound_kind_at_offset(obf, packet, PacketKind::HandshakeInit, HANDSHAKE_INIT_SZ) {
            return &packet[self.inbound_junk_size(PacketKind::HandshakeInit)..];
        }
        if self.inbound_kind_at_offset(
            obf,
            packet,
            PacketKind::HandshakeResponse,
            HANDSHAKE_RESP_SZ,
        ) {
            return &packet[self.inbound_junk_size(PacketKind::HandshakeResponse)..];
        }
        if self.inbound_kind_at_offset(obf, packet, PacketKind::CookieReply, COOKIE_REPLY_SZ) {
            return &packet[self.inbound_junk_size(PacketKind::CookieReply)..];
        }

        let junk_size = self.inbound_junk_size(PacketKind::TransportData);
        if junk_size == 0 {
            return packet;
        }

        // Prefer the configured S4 offset before the plain offset-0 fallback.
        // S4 junk can itself start with a value inside H4; checking offset 0
        // first would leave valid padded transport packets unstripped.
        if packet.len() >= junk_size + DATA_OVERHEAD_SZ {
            if Self::read_tag(packet, junk_size)
                .map(|tag| Self::tag_matches(obf, PacketKind::TransportData, tag))
                .unwrap_or(false)
            {
                return &packet[junk_size..];
            }
        }

        if packet.len() >= DATA_OVERHEAD_SZ
            && Self::read_tag(packet, 0)
                .map(|tag| Self::tag_matches(obf, PacketKind::TransportData, tag))
                .unwrap_or(false)
        {
            return packet;
        }

        packet
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

    pub fn prepend_outbound<'a>(
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

                    let stripped = cfg.strip_inbound(obf, &padded);
                    assert_eq!(
                        stripped,
                        original.as_slice(),
                        "roundtrip mismatch: protocol={protocol:?} tag={tag} junk={junk}"
                    );
                }
            }
        }
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
        assert_eq!(cfg.strip_inbound(obf, &init).len(), HANDSHAKE_INIT_SZ);

        let mut resp = vec![0xaa; cfg.response_packet_junk_size as usize + HANDSHAKE_RESP_SZ];
        write_tag(
            &mut resp[cfg.response_packet_junk_size as usize..],
            HANDSHAKE_RESP,
        );
        assert_eq!(cfg.strip_inbound(obf, &resp).len(), HANDSHAKE_RESP_SZ);

        let mut cookie = vec![0xaa; cfg.cookie_packet_junk_size as usize + COOKIE_REPLY_SZ];
        write_tag(
            &mut cookie[cfg.cookie_packet_junk_size as usize..],
            COOKIE_REPLY,
        );
        assert_eq!(cfg.strip_inbound(obf, &cookie).len(), COOKIE_REPLY_SZ);

        let mut data = vec![0xaa; cfg.transport_packet_junk_size as usize + DATA_OVERHEAD_SZ + 8];
        write_tag(&mut data[cfg.transport_packet_junk_size as usize..], DATA);
        assert_eq!(cfg.strip_inbound(obf, &data).len(), DATA_OVERHEAD_SZ + 8);
    }

    #[test]
    fn leaves_inbound_packet_unchanged_when_magic_does_not_match() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(7, 11, 13, 17);
        let mut resp = vec![0xaa; cfg.response_packet_junk_size as usize + HANDSHAKE_RESP_SZ];
        write_tag(&mut resp[cfg.response_packet_junk_size as usize..], DATA);

        assert_eq!(cfg.strip_inbound(obf, &resp).len(), resp.len());
    }

    #[test]
    fn leaves_unpadded_transport_unchanged_when_s4_candidate_is_absent() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(0, 0, 0, 17);
        let mut data = vec![0xaa; DATA_OVERHEAD_SZ + 32];
        write_tag(&mut data, DATA);

        let stripped = cfg.strip_inbound(obf, &data);

        assert_eq!(stripped, data.as_slice());
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

        assert_eq!(stripped, &data[junk_size..]);
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
    fn quic_imitation_uses_short_header_for_every_packet_kind() {
        let cfg = AmneziaConfig::new(8, 9, 10, 11)
            .with_protocol_imitation(AmneziaImitationProtocol::Quic, None);

        // Every S-region is a 1-RTT short header: form bit clear, fixed bit
        // set. A long header would carry a length field that cannot frame the
        // WireGuard packet that follows, and S2/S3 are far below the 1200-byte
        // minimum a valid Initial requires (RFC 9000 §14.1).
        let cases = [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ, 8usize),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ, 9),
            (COOKIE_REPLY, COOKIE_REPLY_SZ, 10),
            (DATA, DATA_OVERHEAD_SZ + 4, 11),
        ];

        for (tag, packet_size, junk_size) in cases {
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
        let cfg = AmneziaConfig::new(0, 0, 0, 0)
            .with_pre_handshake_junk(1, 0, 0, 0)
            .with_protocol_imitation(AmneziaImitationProtocol::Quic, None);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut buffer = vec![0u8; QUIC_JUNK_SIZE_MAX];

        let junk = cfg.fill_pre_handshake_junk(&mut buffer, &mut rng).unwrap();

        assert!(
            junk.len() >= 1200,
            "a long-header Initial needs a >=1200 byte datagram, got {}",
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
}
