# QUIC Initial test fixtures

Ground-truth browser QUIC Initial packets used to calibrate and verify the
imitation profiles in `../profiles.rs` / `../tls.rs`.

| File | Source |
|------|--------|
| `chrome_147_initial.bin` | Chrome 147 stable, IPv4 / UDP 443 |
| `firefox_149_initial.bin` | Firefox 149 stable, IPv4 / UDP 443 |

Each file holds the two client Initial packets of a single real QUIC flow
(a modern ClientHello with an MLKEM768 key share spans two Initials), stored as
length-prefixed records: a 2-byte big-endian length followed by the raw QUIC
Initial (UDP payload) bytes, repeated.

They were extracted from the `.pcapng` captures in the wiresock repository at
`netlib/test/quic/captures/` — see that directory's `README.md` for the full
documented field values. The fixtures are decrypted in `../fingerprint.rs` using
this crate's own RFC 9001 Initial crypto, so they double as a real-world
known-answer test for the crypto layer.

To target a newer browser version: capture its QUIC Initials, replace the
corresponding `.bin` (both Initials of one flow, length-prefixed as above), and
update the matching profile in `../profiles.rs` until the parity tests pass.
