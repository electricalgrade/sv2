// sv2_src/sv2/sv2_wire.h
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define SV2_EXT_COMMON 0x0000

// Common messages (subset)
#define SV2_MSG_SETUP_CONNECTION          0x00
#define SV2_MSG_SETUP_CONNECTION_SUCCESS  0x01

typedef struct {
    uint16_t ext;
    uint8_t  msg_type;
    const uint8_t *payload;
    size_t   len;
} sv2_frame_t;

// len-prefixed I/O (2-byte big-endian length)
int  sv2_read_len_prefixed(int fd, uint8_t *buf, size_t cap, size_t *out_len);
int  sv2_write_len_prefixed(int fd, const uint8_t *buf, size_t len);

// Build/parse a simple SV2 frame: [u16 ext][u8 msg_type][payload...]
int  sv2_parse_frame(const uint8_t *buf, size_t n, sv2_frame_t *f);
ssize_t sv2_build_frame(uint8_t *out, size_t cap,
                        uint16_t ext, uint8_t msg_type,
                        const uint8_t *payload, size_t plen);
