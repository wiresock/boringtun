use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;

/// Standard alphabet, accepting a key with or without its trailing `=`.
///
/// `general_purpose::STANDARD` requires canonical padding, which would reject
/// the 43-character unpadded form outright. Both spell the same 32 bytes, and
/// `wg`-style tooling emits the padded one, so accepting either is a kindness
/// to whoever is pasting a key rather than a loosening of what a key may be:
/// the decoded length is still checked below.
const KEY_BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
pub(crate) struct KeyBytes(pub [u8; 32]);

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| "Illegal character in key")?;
                }
            }
            43 | 44 => {
                // Try to parse as base64.
                //
                // The `if let Ok(..)` here used to have no `else`: a string
                // that failed to decode left `internal` at its `[0u8; 32]`
                // initial value and fell through to `Ok(KeyBytes(internal))`
                // below, so an unparseable key was reported as a successfully
                // parsed ALL-ZERO one. Nothing downstream rejects that -- a
                // zero `preshared_key` is indistinguishable from none, and
                // `Device::set_key` will happily adopt a zero static secret --
                // so a single mistyped character silently disabled the PSK or
                // swapped in a publicly known identity, with the API returning
                // success either way.
                //
                // `Indifferent` padding, so the `43` in the arm above means
                // something: the default `STANDARD` engine requires canonical
                // padding, under which a 43-character unpadded key can never
                // decode. That arm could therefore only ever produce the
                // all-zero key, which is how this stayed hidden.
                match KEY_BASE64.decode(s) {
                    Ok(decoded_key) if decoded_key.len() == internal.len() => {
                        internal[..].copy_from_slice(&decoded_key);
                    }
                    _ => return Err("Illegal character in key"),
                }
            }
            _ => return Err("Illegal key size"),
        }

        Ok(KeyBytes(internal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// The `Engine` migration must not have changed the alphabet or the padding.
    ///
    /// `base64::decode` was a shim for `STANDARD.decode`, so this should hold by
    /// construction -- but "should, by construction" is what a wire format
    /// regression sounds like the day before it bites. WireGuard keys are
    /// standard base64 with padding; a switch to the URL-safe alphabet or to
    /// `NO_PAD` would silently reject every real config, and only at the point
    /// where a user pastes a key.
    #[test]
    fn keys_still_parse_as_padded_standard_base64() {
        // A known 32-byte key and its standard-alphabet, padded encoding.
        // `+` and `/` appear in it, which is exactly where the URL-safe
        // alphabet would diverge.
        let raw: [u8; 32] = [
            0xfb, 0xff, 0xbe, 0x3f, 0xf8, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
            0x70, 0x80, 0x90, 0xa0,
        ];
        let encoded = KEY_BASE64.encode(raw);
        assert!(
            encoded.contains('+') || encoded.contains('/'),
            "this vector must exercise the two characters the URL-safe alphabet changes: {}",
            encoded
        );
        assert!(
            encoded.ends_with('='),
            "standard base64 keys are padded: {}",
            encoded
        );
        assert_eq!(encoded.len(), 44, "32 bytes padded is 44 characters");

        let parsed = KeyBytes::from_str(&encoded).expect("a padded standard key must parse");
        assert_eq!(parsed.0, raw);
    }

    /// The 32 bytes used throughout, and their canonical padded encoding.
    const RAW: [u8; 32] = [0xab; 32];
    const PADDED: &str = "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=";

    fn parse(s: &str) -> Result<[u8; 32], &'static str> {
        KeyBytes::from_str(s).map(|k| k.0)
    }

    #[test]
    fn a_key_that_does_not_decode_is_an_error_not_the_all_zero_key() {
        // Each of these previously returned Ok([0u8; 32]).
        for (label, s) in [
            ("undecodable, 44 chars", "!".repeat(44)),
            ("undecodable, 43 chars", "!".repeat(43)),
            // The URL-safe alphabet: valid base64 elsewhere, not here.
            (
                "url-safe alphabet",
                "-_--P_gAESIzRFVmd4iZqrvM3e7_ABAgMEBQYHCAkKA=".to_string(),
            ),
        ] {
            assert_eq!(
                parse(&s),
                Err("Illegal character in key"),
                "{}: must be refused, not silently zeroed",
                label
            );
        }
    }

    /// The realistic case: one mistyped character in an otherwise good key.
    ///
    /// The review that found this measured 48 of the 63 other standard-alphabet
    /// characters in the final data position producing the all-zero key, so
    /// this was the common outcome of a typo, not a corner.
    #[test]
    fn a_single_character_typo_is_never_silently_accepted() {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut zeroed = 0;
        for &c in ALPHABET {
            let mut typo: Vec<u8> = PADDED.as_bytes().to_vec();
            if typo[42] == c {
                continue; // not a typo
            }
            typo[42] = c;
            let typo = String::from_utf8(typo).unwrap();
            match parse(&typo) {
                Err(_) => {}
                Ok(k) => {
                    assert_ne!(k, [0u8; 32], "typo '{}' produced the all-zero key", typo);
                    assert_ne!(k, RAW, "typo '{}' produced the original key", typo);
                    zeroed += 1; // decoded to some other valid key: acceptable
                }
            }
        }
        // A typo may legitimately name a different key; it may never name the
        // all-zero one, and the assertions above are what enforce that.
        assert!(zeroed <= ALPHABET.len(), "sanity");
    }

    #[test]
    fn both_the_padded_and_unpadded_forms_parse_to_the_same_key() {
        assert_eq!(PADDED.len(), 44);
        let unpadded = PADDED.trim_end_matches('=');
        assert_eq!(unpadded.len(), 43);

        assert_eq!(parse(PADDED), Ok(RAW), "the canonical padded form");
        assert_eq!(parse(unpadded), Ok(RAW), "the 43-character unpadded form");
    }

    /// The all-zero key is a legitimate 32-byte value. Refusing undecodable
    /// input must not become refusing this, or the fix would have swapped one
    /// wrong answer for another.
    #[test]
    fn a_genuinely_all_zero_key_still_parses() {
        let encoded = KEY_BASE64.encode([0u8; 32]);
        assert_eq!(encoded.len(), 44);
        assert_eq!(parse(&encoded), Ok([0u8; 32]));
    }

    #[test]
    fn the_hex_form_is_unaffected() {
        let hex: String = RAW.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex.len(), 64);
        assert_eq!(parse(&hex), Ok(RAW));
        let mut bad = hex.clone();
        bad.replace_range(0..1, "z");
        assert_eq!(parse(&bad), Err("Illegal character in key"));
    }

    #[test]
    fn a_wrong_length_string_is_still_a_size_error() {
        assert_eq!(parse(&"A".repeat(45)), Err("Illegal key size"));
        assert_eq!(parse(""), Err("Illegal key size"));
    }
}
