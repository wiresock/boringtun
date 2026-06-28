// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! RFC 9001 QUIC Initial cryptography for the imitation generator.
//!
//! Only the *client* Initial keys are derived — the imitation produces a
//! browser-shaped Initial packet and never decrypts server traffic.
//!
//! HKDF-SHA256, HMAC-SHA256, and AES-128-GCM come from `ring`; the single-block
//! AES-128-ECB used for header protection (which `ring` does not expose) comes
//! from the `aes` crate.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hmac;

/// RFC 9001 §5.2 Initial salt for QUIC v1.
pub(crate) const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

pub(crate) const AES_KEY_LEN: usize = 16;
pub(crate) const AES_GCM_IV_LEN: usize = 12;
pub(crate) const AES_GCM_TAG_LEN: usize = 16;

/// Client Initial secrets derived from the Destination Connection ID.
pub(crate) struct InitialKeys {
    pub key: [u8; AES_KEY_LEN],
    pub iv: [u8; AES_GCM_IV_LEN],
    pub hp: [u8; AES_KEY_LEN],
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// HKDF-Extract (RFC 5869) with SHA-256.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand (RFC 5869) with SHA-256.
fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < len {
        let mut msg = Vec::with_capacity(prev.len() + info.len() + 1);
        msg.extend_from_slice(&prev);
        msg.extend_from_slice(info);
        msg.push(counter);
        let block = hmac_sha256(prk, &msg);
        out.extend_from_slice(&block);
        prev = block.to_vec();
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// HKDF-Expand-Label (RFC 8446 §7.1) with the empty context QUIC/TLS 1.3 uses.
fn hkdf_expand_label(secret: &[u8], label: &str, len: usize) -> Vec<u8> {
    const PREFIX: &[u8] = b"tls13 ";
    let label_len = PREFIX.len() + label.len();
    let mut info = Vec::with_capacity(2 + 1 + label_len + 1);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(label_len as u8);
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(label.as_bytes());
    info.push(0); // empty context
    hkdf_expand(secret, &info, len)
}

/// Derive the client Initial key/iv/hp from `salt` and the Destination
/// Connection ID, per RFC 9001 §5.2.
pub(crate) fn derive_initial_keys(salt: &[u8], dcid: &[u8]) -> InitialKeys {
    let initial_secret = hkdf_extract(salt, dcid);
    let client_secret = hkdf_expand_label(&initial_secret, "client in", 32);
    let key = hkdf_expand_label(&client_secret, "quic key", AES_KEY_LEN);
    let iv = hkdf_expand_label(&client_secret, "quic iv", AES_GCM_IV_LEN);
    let hp = hkdf_expand_label(&client_secret, "quic hp", AES_KEY_LEN);

    let mut keys = InitialKeys {
        key: [0u8; AES_KEY_LEN],
        iv: [0u8; AES_GCM_IV_LEN],
        hp: [0u8; AES_KEY_LEN],
    };
    keys.key.copy_from_slice(&key);
    keys.iv.copy_from_slice(&iv);
    keys.hp.copy_from_slice(&hp);
    keys
}

/// AES-128-GCM seal. Returns `ciphertext || tag`.
///
/// `pn` is the encoded packet-number bytes (1..=4), XORed right-aligned into the
/// IV to form the nonce per RFC 9001 §5.3.
pub(crate) fn aes_128_gcm_seal(
    key: &[u8; AES_KEY_LEN],
    iv: &[u8; AES_GCM_IV_LEN],
    pn: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    debug_assert!(pn.len() <= AES_GCM_IV_LEN);
    let mut nonce = *iv;
    let off = AES_GCM_IV_LEN - pn.len();
    for (i, b) in pn.iter().enumerate() {
        nonce[off + i] ^= b;
    }

    let unbound = UnboundKey::new(&AES_128_GCM, key).expect("valid AES-128 key");
    let sealing = LessSafeKey::new(unbound);
    let mut buf = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut buf,
        )
        .expect("AES-128-GCM seal cannot fail for valid inputs");
    buf
}

/// AES-128-ECB single-block encryption used to derive the header-protection
/// mask (RFC 9001 §5.4.3).
pub(crate) fn aes_ecb_block(key: &[u8; AES_KEY_LEN], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut b = *block;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut b));
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9001 Appendix A.1: client Initial keys for DCID 0x8394c8f03e515708.
    #[test]
    fn rfc9001_appendix_a1_client_initial_keys() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = derive_initial_keys(&INITIAL_SALT_V1, &dcid);

        assert_eq!(hex::encode(keys.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex::encode(keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex::encode(keys.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    /// FIPS-197 Appendix B AES-128 single-block known-answer vector.
    #[test]
    fn aes128_ecb_fips197_block() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let input = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let out = aes_ecb_block(&key, &input);
        assert_eq!(hex::encode(out), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    /// AES-128-GCM seal must round-trip through `ring`'s open with the same
    /// QUIC-style nonce construction (sanity check on nonce/AAD handling).
    #[test]
    fn aes128_gcm_seal_roundtrips() {
        let key = [0x11u8; AES_KEY_LEN];
        let iv = [0x22u8; AES_GCM_IV_LEN];
        let pn = [0x00, 0x00, 0x00, 0x02];
        let aad = [0xc3, 0x00, 0x00, 0x00, 0x01];
        let plaintext = b"quic initial crypto frame payload";

        let sealed = aes_128_gcm_seal(&key, &iv, &pn, &aad, plaintext);
        assert_eq!(sealed.len(), plaintext.len() + AES_GCM_TAG_LEN);

        // Reconstruct the nonce and open with ring to confirm correctness.
        let mut nonce = iv;
        let off = AES_GCM_IV_LEN - pn.len();
        for (i, b) in pn.iter().enumerate() {
            nonce[off + i] ^= b;
        }
        let unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let opening = LessSafeKey::new(unbound);
        let mut buf = sealed.clone();
        let opened = opening
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut buf,
            )
            .unwrap();
        assert_eq!(opened, plaintext);
    }
}
