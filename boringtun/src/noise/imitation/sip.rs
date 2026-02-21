// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! SIP INVITE + CANCEL imitation (RFC 3261), ported from wiresock's
//! `simulate_sip_request`.
//!
//! Emits two client packets: an INVITE, then a matching CANCEL (RFC 3261 §9.1 —
//! a UAC aborting a pending INVITE before any response). The CANCEL reuses the
//! INVITE's Via branch, To/From tags, Call-ID and CSeq number. No server
//! responses are synthesized.

use rand_core::RngCore;

/// Realistic SIP UAC header profiles (User-Agent / Allow / Supported), kept
/// self-consistent and rotated to avoid a single fixed header signature.
struct SipProfile {
    user_agent: &'static str,
    allow: &'static str,
    supported: &'static str,
}

const SIP_PROFILES: [SipProfile; 6] = [
    SipProfile {
        user_agent: "PJSUA v2.13 Linux-6.1/x86_64",
        allow: "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, PRACK, UPDATE, REFER, NOTIFY, MESSAGE, SUBSCRIBE",
        supported: "100rel, timer, replaces, norefersub",
    },
    SipProfile {
        user_agent: "Linphone/5.2.5 (belle-sip/5.2.0)",
        allow: "INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, UPDATE, REFER, MESSAGE",
        supported: "replaces, outbound, gruu, path, 100rel, timer",
    },
    SipProfile {
        user_agent: "Twinkle/1.10.2",
        allow: "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, INFO",
        supported: "replaces, timer, 100rel",
    },
    SipProfile {
        user_agent: "Zoiper rv2.10.16.6",
        allow: "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, PRACK, UPDATE, REFER, NOTIFY",
        supported: "timer, 100rel, replaces, norefersub",
    },
    SipProfile {
        user_agent: "MicroSIP/3.21.5",
        allow: "ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, REFER, SUBSCRIBE",
        supported: "replaces, 100rel, timer",
    },
    SipProfile {
        user_agent: "Bria 5.6.4",
        allow: "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, REFER, NOTIFY, MESSAGE",
        supported: "replaces, timer, 100rel",
    },
];

const NAMES: [&str; 25] = [
    "alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi", "ivan", "judy", "trent",
    "victor", "walter", "olivia", "noah", "emma", "sofia", "lucas", "mason", "ava", "support",
    "sales", "billing", "admin", "noc",
];

fn hex32(v: u32) -> String {
    format!("{:08x}", v)
}

fn octet(rng: &mut impl RngCore) -> u32 {
    2 + rng.next_u32() % 253 // [2, 254], avoiding network/broadcast literals
}

/// A random RFC 1918 IPv4 literal across the three private ranges.
fn rfc1918_literal(rng: &mut impl RngCore) -> String {
    match rng.next_u32() % 3 {
        0 => format!("10.{}.{}.{}", octet(rng), octet(rng), octet(rng)),
        1 => format!(
            "172.{}.{}.{}",
            16 + rng.next_u32() % 16,
            octet(rng),
            octet(rng)
        ),
        _ => format!("192.168.{}.{}", octet(rng), octet(rng)),
    }
}

/// A random SIP local-part (name, name+digits, extension number, or hex token).
fn random_sip_username(rng: &mut impl RngCore) -> String {
    match rng.next_u32() % 4 {
        0 => NAMES[(rng.next_u32() % NAMES.len() as u32) as usize].to_string(),
        1 => format!(
            "{}{}",
            NAMES[(rng.next_u32() % NAMES.len() as u32) as usize],
            rng.next_u32() % 1000
        ),
        2 => format!("{}", 100 + rng.next_u32() % 999_900),
        _ => format!("{:08x}", rng.next_u32()),
    }
}

/// Capitalize the first character if it is an ASCII letter (display name).
fn display_name(name: &str) -> String {
    let mut c = name.chars();
    match c.next() {
        Some(first) if first.is_ascii_alphabetic() => {
            first.to_ascii_uppercase().to_string() + c.as_str()
        }
        _ => name.to_string(),
    }
}

/// Generate the INVITE and CANCEL datagrams for a SIP call to `domain`.
pub(crate) fn generate(domain: &str, rng: &mut impl RngCore) -> Vec<Vec<u8>> {
    let branch_id = format!("z9hG4bK{}{}", hex32(rng.next_u32()), hex32(rng.next_u32()));
    let from_tag = format!("{}{}", hex32(rng.next_u32()), hex32(rng.next_u32()));
    let call_id_val = rng.next_u32();
    let call_id_val2 = rng.next_u32();
    let cseq_num = 10000 + rng.next_u32() % 90000;

    let call_id_host = match rng.next_u32() % 3 {
        0 => rfc1918_literal(rng),
        1 => {
            const TLDS: [&str; 4] = ["net", "com", "org", "local"];
            format!(
                "{}.{}",
                hex32(call_id_val ^ 0xa5a5_a5a5),
                TLDS[(rng.next_u32() % 4) as usize]
            )
        }
        _ => hex32(call_id_val ^ 0xc3c3_c3c3),
    };
    let call_id = format!(
        "{}{}@{}",
        hex32(call_id_val),
        hex32(call_id_val2),
        call_id_host
    );

    let via_host = format!(
        "{}:{}",
        rfc1918_literal(rng),
        49152 + rng.next_u32() % 16384
    );
    let profile = &SIP_PROFILES[(rng.next_u32() % SIP_PROFILES.len() as u32) as usize];

    let caller = random_sip_username(rng);
    let mut callee = random_sip_username(rng);
    if callee == caller {
        callee = random_sip_username(rng);
    }
    let caller_display = display_name(&caller);
    let callee_display = display_name(&callee);

    let mut invite = String::with_capacity(700);
    invite.push_str(&format!("INVITE sip:{callee}@{domain} SIP/2.0\r\n"));
    invite.push_str(&format!(
        "Via: SIP/2.0/UDP {via_host};branch={branch_id};rport\r\n"
    ));
    invite.push_str("Max-Forwards: 70\r\n");
    invite.push_str(&format!(
        "From: {caller_display} <sip:{caller}@{domain}>;tag={from_tag}\r\n"
    ));
    invite.push_str(&format!("To: {callee_display} <sip:{callee}@{domain}>\r\n"));
    invite.push_str(&format!("Call-ID: {call_id}\r\n"));
    invite.push_str(&format!("CSeq: {cseq_num} INVITE\r\n"));
    invite.push_str(&format!("Contact: <sip:{caller}@{via_host}>\r\n"));
    invite.push_str(&format!("User-Agent: {}\r\n", profile.user_agent));
    invite.push_str(&format!("Allow: {}\r\n", profile.allow));
    invite.push_str(&format!("Supported: {}\r\n", profile.supported));
    invite.push_str("Content-Length: 0\r\n\r\n");

    // CANCEL must match the INVITE in Via branch, To/From tags, Call-ID and CSeq
    // number (RFC 3261 §9.1).
    let mut cancel = String::with_capacity(300);
    cancel.push_str(&format!("CANCEL sip:{callee}@{domain} SIP/2.0\r\n"));
    cancel.push_str(&format!(
        "Via: SIP/2.0/UDP {via_host};branch={branch_id};rport\r\n"
    ));
    cancel.push_str("Max-Forwards: 70\r\n");
    cancel.push_str(&format!("To: {callee_display} <sip:{callee}@{domain}>\r\n"));
    cancel.push_str(&format!(
        "From: {caller_display} <sip:{caller}@{domain}>;tag={from_tag}\r\n"
    ));
    cancel.push_str(&format!("Call-ID: {call_id}\r\n"));
    cancel.push_str(&format!("CSeq: {cseq_num} CANCEL\r\n"));
    cancel.push_str("Content-Length: 0\r\n\r\n");

    vec![invite.into_bytes(), cancel.into_bytes()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn header<'a>(msg: &'a str, name: &str) -> &'a str {
        msg.lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("missing header {}", name))
    }

    #[test]
    fn invite_and_cancel_are_well_formed_and_match() {
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let packets = generate("voip.example.com", &mut rng);
        assert_eq!(packets.len(), 2);

        let invite = std::str::from_utf8(&packets[0]).unwrap();
        let cancel = std::str::from_utf8(&packets[1]).unwrap();

        assert!(invite.starts_with("INVITE sip:"));
        assert!(invite.contains("@voip.example.com SIP/2.0\r\n"));
        for h in [
            "Via:",
            "Max-Forwards:",
            "From:",
            "To:",
            "Call-ID:",
            "CSeq:",
            "Contact:",
            "User-Agent:",
            "Allow:",
            "Supported:",
            "Content-Length: 0",
        ] {
            assert!(invite.contains(h), "INVITE missing {}", h);
        }
        assert!(invite.contains(";branch=z9hG4bK"));
        assert!(invite.ends_with("\r\n\r\n"));
        assert!(header(invite, "CSeq:").ends_with("INVITE"));

        // RFC 3261 §9.1: CANCEL matches INVITE on Via, Call-ID, From, To; CSeq
        // number identical but method CANCEL.
        assert!(cancel.starts_with("CANCEL sip:"));
        assert_eq!(header(invite, "Via:"), header(cancel, "Via:"));
        assert_eq!(header(invite, "Call-ID:"), header(cancel, "Call-ID:"));
        assert_eq!(header(invite, "From:"), header(cancel, "From:"));
        assert_eq!(header(invite, "To:"), header(cancel, "To:"));
        let cseq_num = |m: &str| {
            header(m, "CSeq:")
                .split_whitespace()
                .nth(1)
                .unwrap()
                .to_string()
        };
        assert_eq!(cseq_num(invite), cseq_num(cancel));
        assert!(header(cancel, "CSeq:").ends_with("CANCEL"));
    }
}
