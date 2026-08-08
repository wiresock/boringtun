use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

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
                // Try to parse as base64
                if let Ok(decoded_key) = BASE64.decode(s) {
                    if decoded_key.len() == internal.len() {
                        internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err("Illegal character in key");
                    }
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
        let encoded = BASE64.encode(raw);
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

    /// The hex path is unaffected by the migration, and still preferred at 64
    /// characters -- pinned so the length dispatch above cannot drift.
    #[test]
    fn hex_keys_still_parse() {
        let raw = [0xabu8; 32];
        let hex: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex.len(), 64);
        assert_eq!(KeyBytes::from_str(&hex).expect("hex must parse").0, raw);
    }
}
