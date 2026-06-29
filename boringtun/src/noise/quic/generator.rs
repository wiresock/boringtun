// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Top-level QUIC Initial imitation: turn a browser profile + SNI into the
//! standalone UDP datagrams a real browser emits when opening a QUIC connection.
//!
//! A modern ClientHello (≈1.4 KB with an MLKEM768 key share) does not fit one
//! Initial, so Chrome/Firefox spill it across two Initials sharing a DCID; curl
//! fits in one. Each datagram is padded to the browser's exact target size.

use super::initial::{build_client_initial, InitialParams};
use super::profiles::{BrowserProfile, Profile};
use super::tls::generate_client_hello;
use rand_core::RngCore;

/// Headroom reserved per packet for the long header, CRYPTO frame overhead, and
/// AEAD tag when choosing the first-packet split point. Comfortably larger than
/// the true overhead (~40 B) so the first fragment always fits with padding.
const PACKET_OVERHEAD_HEADROOM: usize = 64;

fn rand_bytes(n: usize, rng: &mut impl RngCore) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v);
    v
}

/// Resolve `Random` to a concrete browser for this connection (Chrome, Firefox,
/// or curl, matching wgbooster's three-way random selection).
fn resolve(browser: BrowserProfile, rng: &mut impl RngCore) -> BrowserProfile {
    match browser {
        BrowserProfile::Random => match rng.next_u32() % 3 {
            0 => BrowserProfile::Chrome,
            1 => BrowserProfile::Firefox,
            _ => BrowserProfile::Curl,
        },
        other => other,
    }
}

/// Generate the QUIC Initial datagram(s) imitating `browser` opening a
/// connection to `sni`. Returns one datagram for curl, two for Chrome/Firefox.
pub(crate) fn generate_client_initials(
    browser: BrowserProfile,
    sni: &str,
    rng: &mut impl RngCore,
) -> Vec<Vec<u8>> {
    let resolved = resolve(browser, rng);
    let profile = Profile::for_browser(resolved);

    // Firefox mirrors a 3-byte SCID into transport parameter 0x0f; Chrome/curl
    // use an empty SCID.
    let scid = if resolved == BrowserProfile::Firefox {
        rand_bytes(3, rng)
    } else {
        Vec::new()
    };
    let dcid = rand_bytes(8, rng);
    let client_hello = generate_client_hello(&profile, sni, &scid, rng);
    let target = profile.packet_target;

    let first_len = client_hello
        .len()
        .min(target.saturating_sub(PACKET_OVERHEAD_HEADROOM));
    let mut packets = Vec::with_capacity(2);

    packets.push(build_client_initial(&InitialParams {
        dcid: &dcid,
        scid: &scid,
        packet_number: 0,
        pn_len: 1,
        crypto_offset: 0,
        crypto_payload: &client_hello[..first_len],
        target_size: target,
    }));

    if first_len < client_hello.len() {
        packets.push(build_client_initial(&InitialParams {
            dcid: &dcid,
            scid: &scid,
            packet_number: 1,
            pn_len: 1,
            crypto_offset: first_len as u64,
            crypto_payload: &client_hello[first_len..],
            target_size: target,
        }));
    }

    packets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::quic::fingerprint::fingerprint_of_packets;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn chrome_emits_two_initials_reassembling_to_chrome_fingerprint() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let packets = generate_client_initials(BrowserProfile::Chrome, "example.com", &mut rng);

        assert_eq!(packets.len(), 2, "Chrome ClientHello spans two Initials");
        assert!(
            packets.iter().all(|p| p.len() == 1250),
            "each padded to 1250"
        );

        let fp = fingerprint_of_packets(&packets);
        assert_eq!(fp.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
        assert_eq!(fp.supported_groups, vec![0x11ec, 0x001d, 0x0017, 0x0018]);
        assert_eq!(fp.sni.as_deref(), Some("example.com"));
        assert_eq!(fp.legacy_session_id_len, 0);
    }

    #[test]
    fn firefox_emits_two_initials_with_scid_reassembling_to_firefox_fingerprint() {
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let packets = generate_client_initials(BrowserProfile::Firefox, "example.com", &mut rng);

        assert_eq!(packets.len(), 2);
        assert!(
            packets.iter().all(|p| p.len() == 1252),
            "each padded to 1252"
        );
        // SCID length byte sits right after the 8-byte DCID (offset 1+4+1+8).
        assert_eq!(packets[0][14], 3, "Firefox uses a 3-byte SCID");

        let fp = fingerprint_of_packets(&packets);
        assert_eq!(fp.cipher_suites, vec![0x1301, 0x1303, 0x1302]);
        assert_eq!(
            fp.supported_groups,
            vec![0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]
        );
        assert_eq!(fp.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn curl_emits_single_initial() {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let packets = generate_client_initials(BrowserProfile::Curl, "example.com", &mut rng);

        assert_eq!(packets.len(), 1, "curl fits one Initial");
        assert_eq!(packets[0].len(), 1250);
        let fp = fingerprint_of_packets(&packets);
        assert_eq!(fp.key_share_groups, vec![0x001d]);
        assert_eq!(fp.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn random_resolves_to_chrome_firefox_or_curl() {
        let mut seen_curl = false;
        let mut seen_two_packet = false;
        for seed in 0..32u64 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let packets = generate_client_initials(BrowserProfile::Random, "example.com", &mut rng);
            assert!(packets.len() == 1 || packets.len() == 2);
            let fp = fingerprint_of_packets(&packets);
            // curl shares Chrome's cipher list but advertises only X25519 in
            // key_share and fits a single Initial.
            let is_chrome = fp.cipher_suites == vec![0x1301, 0x1302, 0x1303]
                && fp.key_share_groups == vec![0x11ec, 0x001d];
            let is_firefox = fp.cipher_suites == vec![0x1301, 0x1303, 0x1302];
            let is_curl = fp.key_share_groups == vec![0x001d];
            assert!(
                is_chrome || is_firefox || is_curl,
                "random must be a real profile (seed {seed})"
            );
            seen_curl |= is_curl;
            seen_two_packet |= packets.len() == 2;
        }
        assert!(seen_curl, "random should sometimes pick curl");
        assert!(
            seen_two_packet,
            "random should sometimes pick Chrome/Firefox"
        );
    }
}
