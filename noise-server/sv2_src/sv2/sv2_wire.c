// sv2_src/sv2/sv2_wire.c
#include "sv2_wire.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

static int read_full(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, buf + got, len - got);
        if (r == 0) return -1;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        got += (size_t)r;
    }
    return 0;
}
static int write_full(int fd, const uint8_t *buf, size_t len) {
    size_t n = 0;
    while (n < len) {
        ssize_t r = write(fd, buf + n, len - n);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return -1; }
        n += (size_t)r;
    }
    return 0;
}

int sv2_read_len_prefixed(int fd, uint8_t *buf, size_t cap, size_t *out_len) {
    uint8_t hdr[2];
    if (read_full(fd, hdr, 2) != 0) return -1;
    uint16_t len = ((uint16_t)hdr[0] << 8) | (uint16_t)hdr[1];
    if (len == 0 || len > cap) return -2;
    if (read_full(fd, buf, len) != 0) return -3;
    *out_len = len;
    return 0;
}
int sv2_write_len_prefixed(int fd, const uint8_t *buf, size_t len) {
    if (len > 0xFFFF) return -1;
    uint8_t hdr[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xFF) };
    if (write_full(fd, hdr, 2) != 0) return -2;
    if (write_full(fd, buf, len) != 0) return -3;
    return 0;
}

int sv2_parse_frame(const uint8_t *buf, size_t n, sv2_frame_t *f) {
    if (n < 3) return 0;
    uint16_t ext = ((uint16_t)buf[0] << 8) | (uint16_t)buf[1];
    uint8_t msg  = buf[2];
    f->ext      = ext;
    f->msg_type = msg;
    f->payload  = buf + 3;
    f->len      = n - 3;
    return 1;
}

ssize_t sv2_build_frame(uint8_t *out, size_t cap,
                        uint16_t ext, uint8_t msg_type,
                        const uint8_t *payload, size_t plen) {
    if (cap < 3 + plen) return -1;
    out[0] = (uint8_t)(ext >> 8);
    out[1] = (uint8_t)(ext & 0xFF);
    out[2] = msg_type;
    if (plen) memcpy(out + 3, payload, plen);
    return (ssize_t)(3 + plen);
}
