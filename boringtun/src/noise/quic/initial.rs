// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Assembly of a complete, protected QUIC v1 Initial packet (RFC 9000 §17.2 /
//! RFC 9001 §5) carrying a TLS ClientHello in a single CRYPTO frame.
//!
//! The browser-specific CRYPTO payload (the ClientHello bytes) and connection
//! ID sizing are supplied by the caller; this module owns the QUIC framing,
//! padding-to-target, AEAD, and header protection.

use super::crypto::{self, AES_GCM_TAG_LEN};
use super::varint;
use std::convert::TryInto;

const VERSION_V1: u32 = 0x0000_0001;
const FRAME_CRYPTO: u8 = 0x06;

/// Inputs for a single client Initial packet.
pub(crate) struct InitialParams<'a> {
    /// Destination Connection ID (also seeds the Initial keys).
    pub dcid: &'a [u8],
    /// Source Connection ID (may be empty, e.g. Chrome 131+).
    pub scid: &'a [u8],
    /// Packet number (truncated to `pn_len` bytes, big-endian).
    pub packet_number: u32,
    /// Encoded packet-number length in bytes, 1..=4.
    pub pn_len: usize,
    /// The TLS ClientHello bytes carried in a single CRYPTO frame at offset 0.
    pub crypto_payload: &'a [u8],
    /// Target total UDP datagram size (e.g. 1250 for Chrome). PADDING frames
    /// fill the remainder; if the base packet already exceeds the target no
    /// padding is added.
    pub target_size: usize,
}

/// Fixed long-header overhead, excluding the variable Length field and packet
/// number: first byte + version + dcid_len + dcid + scid_len + scid + token_len.
fn fixed_header_len(dcid: usize, scid: usize) -> usize {
    1 + 4 + 1 + dcid + 1 + scid + 1
}

/// Exact long-header size for a given plaintext payload length.
fn header_len(dcid: usize, scid: usize, pn_len: usize, payload_len: usize) -> usize {
    let len_field = (pn_len + payload_len + AES_GCM_TAG_LEN) as u64;
    fixed_header_len(dcid, scid) + varint::size(len_field) + pn_len
}

/// Padding (in PADDING frames) needed to make the whole datagram hit
/// `target_size`, accounting for the Length varint possibly growing.
fn padding_for_target(
    dcid: usize,
    scid: usize,
    pn_len: usize,
    base_payload: usize,
    target_size: usize,
) -> usize {
    let mut padding = 0usize;
    for _ in 0..8 {
        let payload = base_payload + padding;
        let total = header_len(dcid, scid, pn_len, payload) + payload + AES_GCM_TAG_LEN;
        match total.cmp(&target_size) {
            std::cmp::Ordering::Equal => return padding,
            std::cmp::Ordering::Less => padding += target_size - total,
            std::cmp::Ordering::Greater => {
                let overshoot = total - target_size;
                let next = padding.saturating_sub(overshoot);
                if next == padding {
                    return padding;
                }
                padding = next;
            }
        }
    }
    padding
}

/// Encode the packet number as `pn_len` big-endian bytes.
fn encode_pn(packet_number: u32, pn_len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; pn_len];
    for (i, slot) in bytes.iter_mut().rev().enumerate() {
        *slot = (packet_number >> (8 * i)) as u8;
    }
    bytes
}

/// Build a complete, protected QUIC v1 client Initial packet.
pub(crate) fn build_client_initial(p: &InitialParams) -> Vec<u8> {
    let pn_len = p.pn_len.clamp(1, 4);
    let keys = crypto::derive_initial_keys(&crypto::INITIAL_SALT_V1, p.dcid);

    // Plaintext payload: one CRYPTO frame at offset 0, then PADDING to target.
    let mut crypto_frame = Vec::with_capacity(p.crypto_payload.len() + 4);
    crypto_frame.push(FRAME_CRYPTO);
    varint::write(&mut crypto_frame, 0); // offset
    varint::write(&mut crypto_frame, p.crypto_payload.len() as u64);
    crypto_frame.extend_from_slice(p.crypto_payload);

    let padding = padding_for_target(
        p.dcid.len(),
        p.scid.len(),
        pn_len,
        crypto_frame.len(),
        p.target_size,
    );
    let mut payload = crypto_frame;
    payload.resize(payload.len() + padding, 0x00); // PADDING frames are 0x00 bytes

    let pn_bytes = encode_pn(p.packet_number, pn_len);
    let len_field = (pn_len + payload.len() + AES_GCM_TAG_LEN) as u64;

    // Unprotected long header. The first byte's low two bits carry pn_len-1.
    let mut header = Vec::with_capacity(header_len(
        p.dcid.len(),
        p.scid.len(),
        pn_len,
        payload.len(),
    ));
    header.push(0xc0 | (pn_len as u8 - 1));
    header.extend_from_slice(&VERSION_V1.to_be_bytes());
    header.push(p.dcid.len() as u8);
    header.extend_from_slice(p.dcid);
    header.push(p.scid.len() as u8);
    header.extend_from_slice(p.scid);
    header.push(0x00); // token length = 0
    varint::write(&mut header, len_field);
    let pn_offset = header.len();
    header.extend_from_slice(&pn_bytes);

    // AEAD: AAD is the full unprotected header (including the packet number).
    let ciphertext = crypto::aes_128_gcm_seal(&keys.key, &keys.iv, &pn_bytes, &header, &payload);

    let mut packet = header;
    packet.extend_from_slice(&ciphertext);

    apply_header_protection(&mut packet, &keys.hp, pn_offset, pn_len);
    packet
}

/// RFC 9001 §5.4.1 header protection for a long-header packet.
fn apply_header_protection(packet: &mut [u8], hp_key: &[u8; 16], pn_offset: usize, pn_len: usize) {
    let sample_offset = pn_offset + 4;
    let sample: [u8; 16] = packet[sample_offset..sample_offset + 16]
        .try_into()
        .expect("packet always padded past the header-protection sample");
    let mask = crypto::aes_ecb_block(hp_key, &sample);

    packet[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};

    /// Reverse header protection + AEAD with the same Initial keys and recover
    /// the plaintext payload, asserting the framing is self-consistent and the
    /// CRYPTO payload survives the round trip.
    fn open_and_extract_crypto(packet: &[u8], dcid: &[u8]) -> Vec<u8> {
        let keys = crypto::derive_initial_keys(&crypto::INITIAL_SALT_V1, dcid);

        // Walk the (unprotected) header fields up to the Length varint to find
        // the packet-number offset.
        let mut pos = 1 + 4; // first byte + version
        let dcid_len = packet[pos] as usize;
        pos += 1 + dcid_len;
        let scid_len = packet[pos] as usize;
        pos += 1 + scid_len;
        let token_len = packet[pos] as usize; // = 0 in our Initials
        pos += 1 + token_len;
        let (length, len_sz) = varint::read(&packet[pos..]).unwrap();
        pos += len_sz;
        let pn_offset = pos;

        // Remove header protection.
        let mut hdr = packet.to_vec();
        let sample_offset = pn_offset + 4;
        let sample: [u8; 16] = hdr[sample_offset..sample_offset + 16].try_into().unwrap();
        let mask = crypto::aes_ecb_block(&keys.hp, &sample);
        hdr[0] ^= mask[0] & 0x0f;
        let pn_len = ((hdr[0] & 0x03) + 1) as usize;
        for i in 0..pn_len {
            hdr[pn_offset + i] ^= mask[1 + i];
        }

        let pn_bytes = hdr[pn_offset..pn_offset + pn_len].to_vec();
        let aad = hdr[..pn_offset + pn_len].to_vec();
        let ciphertext = &hdr[pn_offset + pn_len..pn_offset + (length as usize)];

        let mut nonce = keys.iv;
        let off = nonce.len() - pn_bytes.len();
        for (i, b) in pn_bytes.iter().enumerate() {
            nonce[off + i] ^= b;
        }
        let unbound = UnboundKey::new(&AES_128_GCM, &keys.key).unwrap();
        let opening = LessSafeKey::new(unbound);
        let mut buf = ciphertext.to_vec();
        let plaintext = opening
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut buf,
            )
            .expect("authentication must succeed for a self-built packet");

        // Parse the single CRYPTO frame at the front of the payload.
        assert_eq!(plaintext[0], FRAME_CRYPTO);
        let (offset, o_sz) = varint::read(&plaintext[1..]).unwrap();
        assert_eq!(offset, 0);
        let (data_len, l_sz) = varint::read(&plaintext[1 + o_sz..]).unwrap();
        let start = 1 + o_sz + l_sz;
        plaintext[start..start + data_len as usize].to_vec()
    }

    #[test]
    fn client_initial_hits_target_and_roundtrips() {
        let dcid = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
        let scid = [0x11, 0x22, 0x33];
        let clienthello: Vec<u8> = (0..200u16).map(|i| (i & 0xff) as u8).collect();

        for &target in &[1200usize, 1250, 1252] {
            let params = InitialParams {
                dcid: &dcid,
                scid: &scid,
                packet_number: 2,
                pn_len: 1,
                crypto_payload: &clienthello,
                target_size: target,
            };
            let packet = build_client_initial(&params);

            assert_eq!(packet.len(), target, "must hit target size {target}");
            assert_eq!(packet[0] & 0xc0, 0xc0, "long header, fixed bit set");

            let recovered = open_and_extract_crypto(&packet, &dcid);
            assert_eq!(
                recovered, clienthello,
                "ClientHello survives the round trip"
            );
        }
    }

    #[test]
    fn client_initial_supports_empty_scid() {
        let dcid = [0xaa; 8];
        let clienthello = vec![0x5au8; 300];
        let params = InitialParams {
            dcid: &dcid,
            scid: &[],
            packet_number: 0,
            pn_len: 1,
            crypto_payload: &clienthello,
            target_size: 1250,
        };
        let packet = build_client_initial(&params);
        assert_eq!(packet.len(), 1250);
        assert_eq!(open_and_extract_crypto(&packet, &dcid), clienthello);
    }
}
