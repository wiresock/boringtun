// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Requiring explicit per-fn "Safety" docs not worth it. Just pass in valid
// pointers and buffers/lengths to these, ok?
#![allow(clippy::missing_safety_doc)]

//! C bindings for the BoringTun library
use super::noise::{Tunn, TunnResult};
use crate::noise::amnezia::{AmneziaConfig, AmneziaImitationBrowser, AmneziaImitationProtocol};
use crate::x25519::{PublicKey, StaticSecret};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hex::encode as encode_hex;
use libc::{raise, SIGSEGV};
use parking_lot::Mutex;
use rand_core::OsRng;
use tracing;
use tracing_subscriber::fmt;

use crate::serialization::KeyBytes;
use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Write};
use std::os::raw::c_char;
use std::panic;
use std::ptr;
use std::ptr::null_mut;
use std::slice;
use std::sync::Once;

static PANIC_HOOK: Once = Once::new();

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(CString::new(msg).unwrap_or_else(|_| {
            CString::new("Invalid error message (contains null byte)").unwrap()
        }));
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

/// Returns a pointer to the last error message from any tunnel constructor, or
/// NULL if no error is stored.  The string is valid until the next constructor
/// call on the same thread, or until freed with `last_tunnel_error_free`.
#[no_mangle]
pub extern "C" fn last_tunnel_error() -> *const c_char {
    LAST_ERROR.with(|e| match *e.borrow() {
        Some(ref s) => s.as_ptr(),
        None => ptr::null(),
    })
}

/// Frees the last error string stored by a tunnel constructor.  After this call,
/// `last_tunnel_error` will return NULL until the next failure.
#[no_mangle]
pub extern "C" fn last_tunnel_error_free() {
    clear_last_error();
}

#[allow(non_camel_case_types)]
#[repr(C)]
/// Indicates the operation required from the caller
pub enum result_type {
    /// No operation is required.
    WIREGUARD_DONE = 0,
    /// Write dst buffer to network. Size indicates the number of bytes to write.
    WRITE_TO_NETWORK = 1,
    /// Some error occurred, no operation is required. Size indicates error code.
    WIREGUARD_ERROR = 2,
    /// Write dst buffer to the interface as an ipv4 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV4 = 4,
    /// Write dst buffer to the interface as an ipv6 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV6 = 6,
}

/// The return type of WireGuard functions
#[repr(C)]
pub struct wireguard_result {
    /// The operation to be performed by the caller
    pub op: result_type,
    /// Additional information, required to perform the operation
    pub size: usize,
}

#[repr(C)]
pub struct stats {
    pub time_since_last_handshake: i64,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub estimated_loss: f32,
    pub estimated_rtt: i32,
    reserved: [u8; 56], // Make sure to add new fields in this space, keeping total size constant
}

impl<'a> From<TunnResult<'a>> for wireguard_result {
    fn from(res: TunnResult<'a>) -> wireguard_result {
        match res {
            TunnResult::Done => wireguard_result {
                op: result_type::WIREGUARD_DONE,
                size: 0,
            },
            TunnResult::Err(e) => wireguard_result {
                op: result_type::WIREGUARD_ERROR,
                size: e as _,
            },
            TunnResult::WriteToNetwork(b) => wireguard_result {
                op: result_type::WRITE_TO_NETWORK,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV4(b, _) => wireguard_result {
                op: result_type::WRITE_TO_TUNNEL_IPV4,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV6(b, _) => wireguard_result {
                op: result_type::WRITE_TO_TUNNEL_IPV6,
                size: b.len(),
            },
        }
    }
}

#[repr(C)]
pub struct x25519_key {
    pub key: [u8; 32],
}

/// Generates a new x25519 secret key.
#[no_mangle]
pub extern "C" fn x25519_secret_key() -> x25519_key {
    x25519_key {
        key: StaticSecret::random_from_rng(OsRng).to_bytes(),
    }
}

/// Computes a public x25519 key from a secret key.
#[no_mangle]
pub extern "C" fn x25519_public_key(private_key: x25519_key) -> x25519_key {
    let private = StaticSecret::from(private_key.key);
    let public = PublicKey::from(&private);
    x25519_key {
        key: public.to_bytes(),
    }
}

/// Returns the base64 encoding of a key as a UTF8 C-string.
///
/// The memory has to be freed by calling `x25519_key_to_str_free`
#[no_mangle]
pub extern "C" fn x25519_key_to_base64(key: x25519_key) -> *const c_char {
    let encoded_key = BASE64.encode(key.key);
    CString::into_raw(CString::new(encoded_key).unwrap())
}

/// Returns the hex encoding of a key as a UTF8 C-string.
///
/// The memory has to be freed by calling `x25519_key_to_str_free`
#[no_mangle]
pub extern "C" fn x25519_key_to_hex(key: x25519_key) -> *const c_char {
    let encoded_key = encode_hex(key.key);
    CString::into_raw(CString::new(encoded_key).unwrap())
}

/// Frees memory of the string given by `x25519_key_to_hex` or `x25519_key_to_base64`
///
/// A NULL pointer is a no-op, as `free(NULL)` is in C.
///
/// `*const`, matching `wireguard_ffi.h`, which has always declared this as
/// `void x25519_key_to_str_free(const char *)` -- and matching the two
/// functions that produce the pointer, which return `*const c_char`. The
/// pointer is `*mut` underneath (it came from `CString::into_raw`), so the cast
/// back is sound; taking `*mut` here only forced every caller to cast away a
/// constness this library never really claimed. ABI is unchanged: both are thin
/// pointers.
#[no_mangle]
pub unsafe extern "C" fn x25519_key_to_str_free(stringified_key: *const c_char) {
    if stringified_key.is_null() {
        return;
    }
    drop(CString::from_raw(stringified_key as *mut c_char));
}

/// Check if the input C-string represents a valid base64 encoded x25519 key.
/// Return 1 if valid 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn check_base64_encoded_x25519_key(key: *const c_char) -> i32 {
    let c_str = CStr::from_ptr(key);
    let utf8_key = match c_str.to_str() {
        Err(_) => return 0,
        Ok(string) => string,
    };

    if let Ok(key) = BASE64.decode(utf8_key) {
        let len = key.len();
        let mut zero = 0u8;
        for b in key {
            zero |= b
        }
        if len == 32 && zero != 0 {
            1
        } else {
            0
        }
    } else {
        0
    }
}

/// Custom tracing_subscriber writer to an external function pointer
struct FFIFunctionPointerWriter {
    log_func: unsafe extern "C" fn(*const c_char),
}

/// Implements Write trait for use with tracing_subscriber
impl Write for FFIFunctionPointerWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let out_str = String::from_utf8_lossy(buf).to_string();
        if let Ok(c_string) = CString::new(out_str) {
            unsafe { (self.log_func)(c_string.as_ptr()) }
            Ok(buf.len())
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "Failed to create CString from buffer.",
            ))
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        // no-op
        Ok(())
    }
}

/// Sets the default tracing_subscriber to write to `log_func`.
///
/// Uses Compact format without level, target, thread ids, thread names, or ansi control characters.
/// Subscribes to TRACE level events.
///
/// This function should only be called once as setting the default tracing_subscriber
/// more than once will result in an error.
///
/// Returns false on failure.
///
/// # Safety
///
/// `c_char` will be freed by the library after calling `log_func`. If the value needs
/// to be stored then `log_func` needs to create a copy, e.g. `strcpy`.
#[no_mangle]
pub unsafe extern "C" fn set_logging_function(
    log_func: unsafe extern "C" fn(*const c_char),
) -> bool {
    let result = std::panic::catch_unwind(|| -> bool {
        let writer = FFIFunctionPointerWriter { log_func };
        let format = fmt::format()
            // don't include levels in formatted output
            .with_level(false)
            // don't include targets
            .with_target(false)
            // don't 'include the thread ID of the current thread
            .with_thread_ids(false)
            // don't 'include the name of the current thread
            .with_thread_names(false)
            // use the `Compact` formatting style.
            .compact()
            // disable terminal escape codes
            .with_ansi(false);

        fmt()
            .event_format(format)
            .with_writer(std::sync::Mutex::new(writer))
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .try_init()
            .is_ok()
    });
    if let Ok(value) = result {
        value
    } else {
        false
    }
}

/// Allocate a new tunnel, return NULL on failure.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    new_tunnel_with_amnezia(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        0,
        0,
        0,
        0,
    )
}

// The shared body of the six `extern "C"` tunnel constructors below, which
// take these values as scalars because a C caller cannot pass a Rust type.
// Collapsing the list here would only move the widening one frame outward.
#[allow(clippy::too_many_arguments)]
unsafe fn new_tunnel_with_amnezia_config(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    amnezia: AmneziaConfig,
) -> *mut Mutex<Tunn> {
    if static_private.is_null() {
        set_last_error("Missing static private key");
        return ptr::null_mut();
    }
    if server_static_public.is_null() {
        set_last_error("Missing server static public key");
        return ptr::null_mut();
    }

    let c_str = CStr::from_ptr(static_private);
    let static_private = match c_str.to_str() {
        Err(_) => {
            set_last_error("Invalid static private key: not UTF-8");
            return ptr::null_mut();
        }
        Ok(string) => string,
    };

    let c_str = CStr::from_ptr(server_static_public);
    let server_static_public = match c_str.to_str() {
        Err(_) => {
            set_last_error("Invalid server static public key: not UTF-8");
            return ptr::null_mut();
        }
        Ok(string) => string,
    };

    let preshared_key = if preshared_key.is_null() {
        None
    } else {
        let c_str = CStr::from_ptr(preshared_key);

        if let Ok(string) = c_str.to_str() {
            if let Ok(key) = string.parse::<KeyBytes>() {
                Some(key.0)
            } else {
                set_last_error("Invalid preshared key");
                return null_mut();
            }
        } else {
            set_last_error("Invalid preshared key: not UTF-8");
            return null_mut();
        }
    };

    let private_key = match static_private.parse::<KeyBytes>() {
        Err(_) => {
            set_last_error("Invalid static private key");
            return ptr::null_mut();
        }
        Ok(key) => StaticSecret::from(key.0),
    };

    let public_key = match server_static_public.parse::<KeyBytes>() {
        Err(_) => {
            set_last_error("Invalid server static public key");
            return ptr::null_mut();
        }
        Ok(key) => PublicKey::from(key.0),
    };

    let keep_alive = if keep_alive == 0 {
        None
    } else {
        Some(keep_alive)
    };

    let tunnel = match Tunn::new_with_amnezia(
        private_key,
        public_key,
        preshared_key,
        keep_alive,
        index,
        None,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        amnezia,
    ) {
        Ok(t) => Box::new(Mutex::new(t)),
        Err(e) => {
            tracing::error!(message = "Failed to create tunnel", error = %e);
            set_last_error(&e);
            return ptr::null_mut();
        }
    };

    PANIC_HOOK.call_once(|| {
        // FFI won't properly unwind on panic, but it will if we cause a segmentation fault
        panic::set_hook(Box::new(move |_| {
            raise(SIGSEGV);
        }));
    });

    Box::into_raw(tunnel)
}

/// Allocate a new tunnel with Amnezia S1-S4 junk prefix handling.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        ),
    )
}

/// Allocate a new tunnel with Amnezia pre-handshake junk and S1-S4 junk prefix handling.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia_junk(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
    junk_packet_count: u16,
    junk_packet_size_min: u16,
    junk_packet_size_max: u16,
    junk_packet_delay_ms: u16,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        )
        .with_pre_handshake_junk(
            junk_packet_count,
            junk_packet_size_min,
            junk_packet_size_max,
            junk_packet_delay_ms,
        ),
    )
}

unsafe fn parse_amnezia_imitation(
    imitation_protocol: u8,
    imitation_domain: *const c_char,
) -> Option<(AmneziaImitationProtocol, Option<String>)> {
    let imitation_protocol = match AmneziaImitationProtocol::try_from(imitation_protocol) {
        Ok(protocol) => protocol,
        Err(_) => {
            set_last_error("Invalid Amnezia imitation protocol");
            return None;
        }
    };

    let imitation_domain = if imitation_domain.is_null() {
        None
    } else {
        let c_str = CStr::from_ptr(imitation_domain);
        match c_str.to_str() {
            Ok(domain) => Some(domain.to_owned()),
            Err(_) => None,
        }
    };

    Some((imitation_protocol, imitation_domain))
}

fn parse_amnezia_browser(imitation_browser: u8) -> Option<AmneziaImitationBrowser> {
    match AmneziaImitationBrowser::try_from(imitation_browser) {
        Ok(browser) => Some(browser),
        Err(_) => {
            set_last_error("Invalid Amnezia imitation browser");
            None
        }
    }
}

/// Allocate a new tunnel with Amnezia S1-S4 junk prefix handling and protocol-shaped junk.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia_imitation(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
    imitation_protocol: u8,
    imitation_domain: *const c_char,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    let Some((imitation_protocol, imitation_domain)) =
        parse_amnezia_imitation(imitation_protocol, imitation_domain)
    else {
        return ptr::null_mut();
    };

    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        )
        .with_protocol_imitation(imitation_protocol, imitation_domain),
    )
}

/// Allocate a new tunnel with Amnezia pre-handshake junk, S1-S4 junk prefix
/// handling, and protocol-shaped junk.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia_junk_imitation(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
    junk_packet_count: u16,
    junk_packet_size_min: u16,
    junk_packet_size_max: u16,
    junk_packet_delay_ms: u16,
    imitation_protocol: u8,
    imitation_domain: *const c_char,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    let Some((imitation_protocol, imitation_domain)) =
        parse_amnezia_imitation(imitation_protocol, imitation_domain)
    else {
        return ptr::null_mut();
    };

    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        )
        .with_pre_handshake_junk(
            junk_packet_count,
            junk_packet_size_min,
            junk_packet_size_max,
            junk_packet_delay_ms,
        )
        .with_protocol_imitation(imitation_protocol, imitation_domain),
    )
}

/// Allocate a new tunnel with Amnezia S1-S4 junk prefix handling and a
/// browser-fingerprinted QUIC Initial imitation.
///
/// `imitation_browser` selects the QUIC ClientHello fingerprint (see
/// `enum wireguard_amnezia_browser_profile`); it is only meaningful when
/// `imitation_protocol` is QUIC. An omitted/DEFAULT browser resolves to curl, so
/// a configured QUIC domain always yields a full QUIC Initial.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia_imitation_browser(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
    imitation_protocol: u8,
    imitation_domain: *const c_char,
    imitation_browser: u8,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    let Some((imitation_protocol, imitation_domain)) =
        parse_amnezia_imitation(imitation_protocol, imitation_domain)
    else {
        return ptr::null_mut();
    };
    // The browser is only meaningful for QUIC; for other protocols its value is
    // ignored (AmneziaImitation::new forces Default), so don't reject an
    // out-of-range value there — that would be a surprising constructor failure.
    let imitation_browser = if imitation_protocol == AmneziaImitationProtocol::Quic {
        let Some(browser) = parse_amnezia_browser(imitation_browser) else {
            return ptr::null_mut();
        };
        browser
    } else {
        AmneziaImitationBrowser::Default
    };

    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        )
        .with_protocol_imitation_browser(
            imitation_protocol,
            imitation_domain,
            imitation_browser,
        ),
    )
}

/// Allocate a new tunnel with Amnezia pre-handshake junk, S1-S4 junk prefix
/// handling, and a browser-fingerprinted QUIC Initial imitation.
///
/// As `new_tunnel_with_amnezia_imitation_browser`, plus the Jc/Jmin/Jmax/Jd
/// pre-handshake junk knobs. When a QUIC browser is selected, the standalone
/// browser Initial(s) are emitted before the handshake regardless of Jc.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_with_amnezia_junk_imitation_browser(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    h1_init_start: u32,
    h1_init_end: u32,
    h2_resp_start: u32,
    h2_resp_end: u32,
    h3_cookie_start: u32,
    h3_cookie_end: u32,
    h4_data_start: u32,
    h4_data_end: u32,
    s1_init_junk: u16,
    s2_response_junk: u16,
    s3_cookie_junk: u16,
    s4_transport_junk: u16,
    junk_packet_count: u16,
    junk_packet_size_min: u16,
    junk_packet_size_max: u16,
    junk_packet_delay_ms: u16,
    imitation_protocol: u8,
    imitation_domain: *const c_char,
    imitation_browser: u8,
) -> *mut Mutex<Tunn> {
    clear_last_error();
    let Some((imitation_protocol, imitation_domain)) =
        parse_amnezia_imitation(imitation_protocol, imitation_domain)
    else {
        return ptr::null_mut();
    };
    // The browser is only meaningful for QUIC; for other protocols its value is
    // ignored (AmneziaImitation::new forces Default), so don't reject an
    // out-of-range value there — that would be a surprising constructor failure.
    let imitation_browser = if imitation_protocol == AmneziaImitationProtocol::Quic {
        let Some(browser) = parse_amnezia_browser(imitation_browser) else {
            return ptr::null_mut();
        };
        browser
    } else {
        AmneziaImitationBrowser::Default
    };

    new_tunnel_with_amnezia_config(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
        index,
        h1_init_start,
        h1_init_end,
        h2_resp_start,
        h2_resp_end,
        h3_cookie_start,
        h3_cookie_end,
        h4_data_start,
        h4_data_end,
        AmneziaConfig::new(
            s1_init_junk,
            s2_response_junk,
            s3_cookie_junk,
            s4_transport_junk,
        )
        .with_pre_handshake_junk(
            junk_packet_count,
            junk_packet_size_min,
            junk_packet_size_max,
            junk_packet_delay_ms,
        )
        .with_protocol_imitation_browser(
            imitation_protocol,
            imitation_domain,
            imitation_browser,
        ),
    )
}

/// Drops the Tunn object
///
/// A NULL pointer is a no-op, as `free(NULL)` is in C.
#[no_mangle]
pub unsafe extern "C" fn tunnel_free(tunnel: *mut Mutex<Tunn>) {
    if tunnel.is_null() {
        return;
    }
    drop(Box::from_raw(tunnel));
}

/// Write an IP packet from the tunnel interface.
/// For more details check noise::tunnel_to_network functions.
#[no_mangle]
pub unsafe extern "C" fn wireguard_write(
    tunnel: *const Mutex<Tunn>,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let src = slice::from_raw_parts(src, src_size as usize);
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.encapsulate(src, dst))
}

/// Read a UDP packet from the server.
/// For more details check noise::network_to_tunnel functions.
#[no_mangle]
pub unsafe extern "C" fn wireguard_read(
    tunnel: *const Mutex<Tunn>,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let src = slice::from_raw_parts(src, src_size as usize);
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.decapsulate(None, src, dst))
}

/// This is a state keeping function, that need to be called periodically.
/// Recommended interval: 100ms.
#[no_mangle]
pub unsafe extern "C" fn wireguard_tick(
    tunnel: *const Mutex<Tunn>,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.update_timers(dst))
}

/// Force the tunnel to initiate a new handshake, dst buffer must be at least 148 byte long.
#[no_mangle]
pub unsafe extern "C" fn wireguard_force_handshake(
    tunnel: *const Mutex<Tunn>,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.format_handshake_initiation(dst, true))
}

/// Returns stats from the tunnel:
/// Time of last handshake in seconds (or -1 if no handshake occurred)
/// Number of data bytes encapsulated
/// Number of data bytes decapsulated
#[no_mangle]
pub unsafe extern "C" fn wireguard_stats(tunnel: *const Mutex<Tunn>) -> stats {
    let tunnel = tunnel.as_ref().unwrap().lock();
    let (time, tx_bytes, rx_bytes, estimated_loss, estimated_rtt) = tunnel.stats();
    stats {
        time_since_last_handshake: time.map(|t| t.as_secs() as i64).unwrap_or(-1),
        tx_bytes,
        rx_bytes,
        estimated_loss,
        estimated_rtt: estimated_rtt.map(|r| r as i32).unwrap_or(-1),
        reserved: [0u8; 56],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last_error_string() -> String {
        let error = last_tunnel_error();
        assert!(!error.is_null());
        unsafe { CStr::from_ptr(error) }
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn browser_parser_accepts_known_values_and_rejects_others() {
        last_tunnel_error_free();
        assert_eq!(
            parse_amnezia_browser(0),
            Some(AmneziaImitationBrowser::Default)
        );
        assert_eq!(
            parse_amnezia_browser(1),
            Some(AmneziaImitationBrowser::Chrome)
        );
        assert_eq!(
            parse_amnezia_browser(4),
            Some(AmneziaImitationBrowser::Random)
        );
        assert!(last_tunnel_error().is_null());

        assert_eq!(parse_amnezia_browser(99), None);
        assert_eq!(last_error_string(), "Invalid Amnezia imitation browser");
        last_tunnel_error_free();
    }

    #[test]
    fn browser_constructor_only_validates_browser_for_quic() {
        unsafe {
            let server = CString::new("unused").unwrap();

            // Non-QUIC protocol with an out-of-range browser: the browser is
            // ignored, so the failure is the (null) key, not the browser value.
            last_tunnel_error_free();
            let tunnel = new_tunnel_with_amnezia_imitation_browser(
                ptr::null(),
                server.as_ptr(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                AmneziaImitationProtocol::Dns as u8,
                ptr::null(),
                99, // invalid browser, must be ignored for DNS
            );
            assert!(tunnel.is_null());
            assert_eq!(last_error_string(), "Missing static private key");

            // QUIC with an out-of-range browser still fails on the browser.
            last_tunnel_error_free();
            let tunnel = new_tunnel_with_amnezia_imitation_browser(
                ptr::null(),
                server.as_ptr(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                AmneziaImitationProtocol::Quic as u8,
                ptr::null(),
                99,
            );
            assert!(tunnel.is_null());
            assert_eq!(last_error_string(), "Invalid Amnezia imitation browser");
            last_tunnel_error_free();
        }
    }

    #[test]
    fn imitation_parser_ignores_non_utf8_domain() {
        unsafe {
            last_tunnel_error_free();

            let invalid_domain = [0xffu8, 0];
            let (protocol, domain) = parse_amnezia_imitation(
                AmneziaImitationProtocol::Dns as u8,
                invalid_domain.as_ptr() as *const c_char,
            )
            .unwrap();

            assert_eq!(protocol, AmneziaImitationProtocol::Dns);
            assert_eq!(domain, None);
            assert!(last_tunnel_error().is_null());
            last_tunnel_error_free();
        }
    }

    #[test]
    fn constructor_sets_last_error_for_null_required_key() {
        unsafe {
            last_tunnel_error_free();

            let unused_public = CString::new("unused").unwrap();
            let tunnel = new_tunnel(
                ptr::null(),
                unused_public.as_ptr(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );

            assert!(tunnel.is_null());
            assert_eq!(last_error_string(), "Missing static private key");
            last_tunnel_error_free();
        }
    }

    #[test]
    fn constructor_sets_last_error_for_invalid_utf8_key() {
        unsafe {
            last_tunnel_error_free();

            let invalid_private = [0xffu8, 0];
            let unused_public = CString::new("unused").unwrap();
            let tunnel = new_tunnel(
                invalid_private.as_ptr() as *const c_char,
                unused_public.as_ptr(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );

            assert!(tunnel.is_null());
            assert_eq!(last_error_string(), "Invalid static private key: not UTF-8");
            last_tunnel_error_free();
        }
    }

    #[test]
    fn constructor_sets_last_error_for_invalid_key_text() {
        unsafe {
            last_tunnel_error_free();

            let invalid_private = CString::new("not-a-key").unwrap();
            let unused_public = CString::new("unused").unwrap();
            let tunnel = new_tunnel(
                invalid_private.as_ptr(),
                unused_public.as_ptr(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );

            assert!(tunnel.is_null());
            assert_eq!(last_error_string(), "Invalid static private key");
            last_tunnel_error_free();
        }
    }

    /// The free functions accept NULL, as `free(NULL)` does in C.
    ///
    /// A C caller that frees unconditionally is idiomatic, and the constructors
    /// here return NULL on every error path -- so `tunnel_free(new_tunnel(...))`
    /// after a bad key is a realistic sequence, not a contrived one. Without the
    /// guard these reconstruct a `Box`/`CString` from NULL, which is undefined
    /// behaviour rather than a panic: this test is the only thing standing
    /// between that and a caller who does the ordinary thing.
    #[test]
    fn the_free_functions_accept_null() {
        unsafe {
            tunnel_free(std::ptr::null_mut());
            x25519_key_to_str_free(std::ptr::null());
        }
    }

    /// And still free a real allocation, so the guard did not turn them into
    /// no-ops. Run under a leak detector this would also catch that; here it at
    /// least pins that the non-NULL path is still taken.
    #[test]
    fn the_free_functions_still_free_a_real_pointer() {
        let key = x25519_secret_key();
        // `x25519_key` is `#[repr(C)]` and not `Copy`, so hand each call its own.
        let public = x25519_public_key(x25519_key { key: key.key });

        let s = x25519_key_to_base64(key);
        assert!(!s.is_null());
        unsafe { x25519_key_to_str_free(s) };

        let h = x25519_key_to_hex(public);
        assert!(!h.is_null());
        unsafe { x25519_key_to_str_free(h) };
    }
}
