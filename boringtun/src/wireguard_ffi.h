// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <stdint.h>
#include <stdbool.h>

struct wireguard_tunnel; // This corresponds to the Rust type

enum
{
    MAX_WIREGUARD_PACKET_SIZE = 65536 + 64,
};

enum result_type
{
    WIREGUARD_DONE = 0,
    WRITE_TO_NETWORK = 1,
    WIREGUARD_ERROR = 2,
    WRITE_TO_TUNNEL_IPV4 = 4,
    WRITE_TO_TUNNEL_IPV6 = 6,
};

struct wireguard_result
{
    enum result_type op;
    size_t size;
};

struct stats
{
    int64_t time_since_last_handshake;
    size_t tx_bytes;
    size_t rx_bytes;
    float estimated_loss;
    int32_t estimated_rtt; // rtt estimated on time it took to complete latest initiated handshake in ms
    uint8_t reserved[56];  // decrement appropriately when adding new fields
};

struct x25519_key
{
    uint8_t key[32];
};

// Generates a fresh x25519 secret key
struct x25519_key x25519_secret_key();
// Computes an x25519 public key from a secret key
struct x25519_key x25519_public_key(struct x25519_key private_key);
// Encodes a public or private x25519 key to base64. Must be freed with x25519_key_to_str_free.
const char *x25519_key_to_base64(struct x25519_key key);
// Encodes a public or private x25519 key to hex. Must be freed with x25519_key_to_str_free.
const char *x25519_key_to_hex(struct x25519_key key);
// Free string pointer obtained from either x25519_key_to_base64 or x25519_key_to_hex
void x25519_key_to_str_free(const char *key_str);
// Check if a null terminated string represents a valid x25519 key
// Returns 0 if not
int check_base64_encoded_x25519_key(const char *key);

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
bool set_logging_function(void (*log_func)(const char *));

/// Allocate a new tunnel, returning NULL on failure.
///
/// Keys must be valid base64-encoded 32-byte keys.
/// `preshared_key` may be NULL if no PSK is used.
///
/// ## Amnezia obfuscation tag ranges (H1-H4)
///
/// Each WireGuard packet type has an associated 4-byte "message type" tag.
/// The h1-h4 start/end pairs let you override these tags with inclusive
/// ranges [start, end].  On outgoing packets a value is chosen uniformly
/// at random from the range; on incoming packets any value within the range
/// is accepted for that packet type.
///
/// **Sentinel rules for each (start, end) pair:**
///
/// | start | end   | Resolved range                              |
/// |-------|-------|---------------------------------------------|
/// | 0     | 0     | Default WireGuard constant (1, 2, 3, or 4)  |
/// | S > 0 | 0     | Fixed value [S, S]  (back-compat shorthand) |
/// | S     | E >= S| Custom inclusive range [S, E]                |
/// | S     | E < S | **Invalid** - returns NULL                   |
///
/// **Non-overlap requirement:**
///
/// The four resolved ranges must not overlap (including at boundaries).
/// For example H1=[10, 20] and H4=[20, 30] is rejected because value 20
/// belongs to both.  On conflict the function returns NULL.
///
/// **Quick-start examples:**
///
///   // Standard WireGuard (no obfuscation):
///   new_tunnel(priv, pub, NULL, 25, idx, 0,0, 0,0, 0,0, 0,0);
///
///   // Fixed Amnezia-style tags (single values):
///   new_tunnel(priv, pub, NULL, 25, idx, 10,10, 20,20, 30,30, 40,40);
///
///   // Random tags from non-overlapping ranges:
///   new_tunnel(priv, pub, NULL, 25, idx, 100,199, 200,299, 300,399, 400,499);
///
struct wireguard_tunnel *new_tunnel(const char *static_private,
                                    const char *server_static_public,
                                    const char *preshared_key,
                                    uint16_t keep_alive,       // Keep alive interval in seconds
                                    uint32_t index,            // The 24bit index prefix for session indexes
                                    uint32_t h1_init_start,    // H1 (handshake init) inclusive range start
                                    uint32_t h1_init_end,      // H1 (handshake init) inclusive range end
                                    uint32_t h2_resp_start,    // H2 (handshake resp) inclusive range start
                                    uint32_t h2_resp_end,      // H2 (handshake resp) inclusive range end
                                    uint32_t h3_cookie_start,  // H3 (cookie reply)   inclusive range start
                                    uint32_t h3_cookie_end,    // H3 (cookie reply)   inclusive range end
                                    uint32_t h4_data_start,    // H4 (transport data) inclusive range start
                                    uint32_t h4_data_end);     // H4 (transport data) inclusive range end

// Returns a pointer to the last error message from new_tunnel, or NULL if
// no error is stored.  The pointer is valid until the next call to
// new_tunnel on the same thread, or until freed with last_tunnel_error_free.
const char *last_tunnel_error();

// Frees the last error string stored by new_tunnel.  After this call
// last_tunnel_error will return NULL until the next failure.
void last_tunnel_error_free();

// Deallocate the tunnel
void tunnel_free(struct wireguard_tunnel *);

struct wireguard_result wireguard_write(const struct wireguard_tunnel *tunnel,
                                        const uint8_t *src,
                                        uint32_t src_size,
                                        uint8_t *dst,
                                        uint32_t dst_size);

struct wireguard_result wireguard_read(const struct wireguard_tunnel *tunnel,
                                       const uint8_t *src,
                                       uint32_t src_size,
                                       uint8_t *dst,
                                       uint32_t dst_size);

struct wireguard_result wireguard_tick(const struct wireguard_tunnel *tunnel,
                                       uint8_t *dst,
                                       uint32_t dst_size);

struct wireguard_result wireguard_force_handshake(const struct wireguard_tunnel *tunnel,
                                                  uint8_t *dst,
                                                  uint32_t dst_size);

struct stats wireguard_stats(const struct wireguard_tunnel *tunnel);
