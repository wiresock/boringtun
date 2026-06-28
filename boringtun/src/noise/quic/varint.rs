// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! QUIC variable-length integer encoding (RFC 9000 §16).

/// Number of bytes the variable-length encoding of `value` occupies.
pub(crate) fn size(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

/// Append the variable-length encoding of `value` to `buf`.
///
/// # Panics
/// Panics if `value >= 2^62`, which QUIC varints cannot represent.
pub(crate) fn write(buf: &mut Vec<u8>, value: u64) {
    if value < (1 << 6) {
        buf.push(value as u8);
    } else if value < (1 << 14) {
        buf.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        buf.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        assert!(value < (1 << 62), "value exceeds QUIC varint range");
        buf.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Read a variable-length integer from the front of `input`, returning the
/// value and the number of bytes consumed. Returns `None` if truncated.
#[cfg(test)]
pub(crate) fn read(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for &b in &input[1..len] {
        value = (value << 8) | b as u64;
    }
    Some((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9000_appendix_a1_sample_values() {
        // Encodings from RFC 9000 Appendix A.1.
        for &(value, expected) in &[
            (0u64, "00"),
            (37, "25"),
            (15293, "7bbd"),
            (494878333, "9d7f3e7d"),
            (151288809941952652, "c2197c5eff14e88c"),
        ] {
            let mut buf = Vec::new();
            write(&mut buf, value);
            assert_eq!(hex::encode(&buf), expected, "encode {value}");
            assert_eq!(size(value), buf.len());
            assert_eq!(read(&buf), Some((value, buf.len())), "decode {value}");
        }
    }
}
