// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Browser TLS ClientHello fingerprint profiles, ported from wiresock's
//! `netlib/src/quic/quic_sni_generator.h` and calibrated against the real
//! Chrome 147 / Firefox 149 captures (the fixtures under `testdata/`; see
//! `testdata/README.md` for provenance).
//!
//! Constant fields (cipher suites, groups, signature algorithms, extension set,
//! transport-parameter ids) match the captured browser exactly; per-connection
//! fields (client random, key-share keys, GREASE, connection ids, extension and
//! transport-parameter ordering) are randomized per generated ClientHello via
//! the caller-supplied RNG, as real browsers do.

/// Selectable browser fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrowserProfile {
    Chrome,
    Firefox,
    Curl,
    /// Picks Chrome, Firefox, or curl per generated connection.
    Random,
}

/// X25519MLKEM768 post-quantum hybrid key-exchange codepoint (IANA-registered,
/// not GREASE despite the `0x?A?A`-looking value).
pub(crate) const PQ_HYBRID_GROUP: u16 = 0x11ec;

/// TLS extension type codepoints.
pub(crate) mod ext {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    pub const COMPRESS_CERTIFICATE: u16 = 0x001b;
    pub const RECORD_SIZE_LIMIT: u16 = 0x001c;
    pub const DELEGATED_CREDENTIALS: u16 = 0x0022;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const QUIC_TRANSPORT_PARAMS: u16 = 0x0039;
    pub const APPLICATION_SETTINGS: u16 = 0x44cd;
    pub const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

/// A QUIC transport parameter, resolved to concrete bytes at build time.
#[derive(Debug, Clone)]
pub(crate) enum TpEntry {
    /// Fixed id with a QUIC-varint-encoded value.
    Varint(u64, u64),
    /// Fixed id with raw bytes.
    Bytes(u64, Vec<u8>),
    /// `version_information` (0x11): chosen version + random version-GREASE.
    VersionInfo(u64),
    /// `initial_source_connection_id` (0x0f) set to the long-header SCID.
    ScidSource(u64),
    /// RFC 9000 §18.1 GREASE id (`31k+27`) with 6 random bytes.
    Grease,
}

/// Browser packet-size targets (UDP payload bytes) from the captures.
pub(crate) const CHROME_PACKET_SIZE: usize = 1250;
pub(crate) const FIREFOX_PACKET_SIZE: usize = 1252;

/// A complete ClientHello fingerprint profile.
#[derive(Debug, Clone)]
pub(crate) struct Profile {
    pub name: BrowserProfile,
    pub cipher_suites: Vec<u16>,
    pub extensions_order: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub alpn: Vec<&'static str>,
    pub quic_tp: Vec<TpEntry>,
    pub include_unknown_17613: bool,
    pub use_empty_session_id: bool,
    pub enable_ech: bool,
    pub randomize_extensions_order: bool,
    pub packet_target: usize,
}

impl Profile {
    /// Build a concrete profile. `Random` must be resolved by the caller before
    /// reaching here (the generator does so per connection).
    pub(crate) fn for_browser(browser: BrowserProfile) -> Profile {
        match browser {
            BrowserProfile::Chrome => chrome(),
            BrowserProfile::Firefox => firefox(),
            BrowserProfile::Curl => curl(),
            BrowserProfile::Random => {
                unreachable!("BrowserProfile::Random must be resolved before for_browser")
            }
        }
    }
}

/// Chromium-family profile (Chrome 147 calibration).
fn chrome() -> Profile {
    use ext::*;
    Profile {
        name: BrowserProfile::Chrome,
        cipher_suites: vec![0x1301, 0x1302, 0x1303],
        extensions_order: vec![
            SERVER_NAME,
            SUPPORTED_GROUPS,
            SIGNATURE_ALGORITHMS,
            ALPN,
            COMPRESS_CERTIFICATE,
            SUPPORTED_VERSIONS,
            PSK_KEY_EXCHANGE_MODES,
            KEY_SHARE,
            QUIC_TRANSPORT_PARAMS,
            APPLICATION_SETTINGS,
            ENCRYPTED_CLIENT_HELLO,
        ],
        supported_groups: vec![PQ_HYBRID_GROUP, 0x001d, 0x0017, 0x0018],
        signature_algorithms: vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
        ],
        supported_versions: vec![0x0304],
        key_share_groups: vec![PQ_HYBRID_GROUP, 0x001d],
        alpn: vec!["h3"],
        quic_tp: vec![
            TpEntry::Varint(0x04, 15_728_640),
            TpEntry::Bytes(0x0f, vec![]),
            TpEntry::Varint(0x07, 6_291_456),
            TpEntry::Varint(0x05, 6_291_456),
            TpEntry::Varint(0x03, 1472),
            TpEntry::Varint(0x06, 6_291_456),
            TpEntry::Varint(0x08, 100),
            TpEntry::Varint(0x3127, 18196),
            TpEntry::Varint(0x20, 65536),
            TpEntry::VersionInfo(0x11),
            TpEntry::Varint(0x01, 30000),
            TpEntry::Varint(0x09, 103),
            TpEntry::Grease,
        ],
        include_unknown_17613: true,
        use_empty_session_id: true,
        enable_ech: true,
        randomize_extensions_order: true,
        packet_target: CHROME_PACKET_SIZE,
    }
}

/// Mozilla Firefox profile (Firefox 149 calibration).
fn firefox() -> Profile {
    use ext::*;
    Profile {
        name: BrowserProfile::Firefox,
        cipher_suites: vec![0x1301, 0x1303, 0x1302],
        extensions_order: vec![
            SERVER_NAME,
            STATUS_REQUEST,
            DELEGATED_CREDENTIALS,
            SIGNATURE_ALGORITHMS,
            SUPPORTED_GROUPS,
            EXTENDED_MASTER_SECRET,
            RENEGOTIATION_INFO,
            RECORD_SIZE_LIMIT,
            PSK_KEY_EXCHANGE_MODES,
            COMPRESS_CERTIFICATE,
            KEY_SHARE,
            ALPN,
            SUPPORTED_VERSIONS,
            QUIC_TRANSPORT_PARAMS,
            ENCRYPTED_CLIENT_HELLO,
        ],
        supported_groups: vec![PQ_HYBRID_GROUP, 0x001d, 0x0017, 0x0018, 0x0019],
        signature_algorithms: vec![
            0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201,
        ],
        supported_versions: vec![0x0304],
        key_share_groups: vec![PQ_HYBRID_GROUP, 0x001d, 0x0017],
        alpn: vec!["h3"],
        quic_tp: vec![
            TpEntry::Varint(0x01, 30000),
            TpEntry::Varint(0x04, 25_165_824),
            TpEntry::Varint(0x05, 12_582_912),
            TpEntry::Varint(0x06, 1_048_576),
            TpEntry::Varint(0x07, 1_048_576),
            TpEntry::Varint(0x08, 100),
            TpEntry::Varint(0x09, 100),
            TpEntry::Varint(0x0b, 20),
            TpEntry::Varint(0x0e, 8),
            TpEntry::ScidSource(0x0f),
            TpEntry::VersionInfo(0x11),
            TpEntry::Bytes(0xff02de1a, vec![0x43, 0xe8]),
            TpEntry::Varint(0x20, 65535),
        ],
        include_unknown_17613: false,
        // Calibrated to the Firefox 149 capture, which carries an empty
        // legacy_session_id under ECH (wgbooster's literal profile predates
        // this and is corrected here against ground truth).
        use_empty_session_id: true,
        enable_ech: true,
        randomize_extensions_order: true,
        packet_target: FIREFOX_PACKET_SIZE,
    }
}

/// Minimal cURL-like profile (single CRYPTO frame, no capture ground truth).
fn curl() -> Profile {
    use ext::*;
    Profile {
        name: BrowserProfile::Curl,
        cipher_suites: vec![0x1301, 0x1302, 0x1303],
        extensions_order: vec![
            SERVER_NAME,
            SUPPORTED_VERSIONS,
            SUPPORTED_GROUPS,
            SIGNATURE_ALGORITHMS,
            ALPN,
            KEY_SHARE,
            PSK_KEY_EXCHANGE_MODES,
            QUIC_TRANSPORT_PARAMS,
            COMPRESS_CERTIFICATE,
            ENCRYPTED_CLIENT_HELLO,
        ],
        supported_groups: vec![0x001d, 0x0017, 0x0018],
        signature_algorithms: vec![0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806],
        supported_versions: vec![0x0304],
        key_share_groups: vec![0x001d],
        alpn: vec!["h3"],
        quic_tp: vec![
            TpEntry::Varint(0x01, 30000),
            TpEntry::Varint(0x03, 1472),
            TpEntry::Varint(0x04, 10_485_760),
            TpEntry::Varint(0x05, 5_242_880),
            TpEntry::Varint(0x06, 5_242_880),
            TpEntry::Varint(0x07, 5_242_880),
            TpEntry::Varint(0x08, 100),
            TpEntry::Varint(0x09, 100),
            TpEntry::Varint(0x0e, 2),
            TpEntry::Bytes(0x0f, vec![]),
        ],
        include_unknown_17613: false,
        use_empty_session_id: false,
        enable_ech: true,
        randomize_extensions_order: false,
        packet_target: CHROME_PACKET_SIZE,
    }
}
