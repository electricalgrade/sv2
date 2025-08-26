#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>

// Minimal structs for SV2 SetupConnection and SetupConnection.Success

typedef struct {
    uint8_t  protocol;      // expected 2
    uint16_t min_version;   // big-endian on the wire
    uint16_t max_version;   // big-endian on the wire
    char     vendor[64];    // ASCII, null-terminated after decode
} sv2_SetupConnection;

typedef struct {
    uint16_t used_version;  // big-endian on the wire
    uint32_t flags;         // big-endian on the wire
} sv2_SetupConnectionSuccess;

// Payload encoders/decoders (NOT length-prefixed, NOT framed)
// Wrap with sv2_build_frame()/sv2_parse_frame().

ssize_t sv2_enc_setup_connection(
    uint8_t *out, size_t cap, const sv2_SetupConnection *m);

int sv2_dec_setup_connection(
    const uint8_t *buf, size_t len, sv2_SetupConnection *out);

ssize_t sv2_enc_setup_connection_success(
    uint8_t *out, size_t cap, const sv2_SetupConnectionSuccess *m);

int sv2_dec_setup_connection_success(
    const uint8_t *buf, size_t len, sv2_SetupConnectionSuccess *out);
