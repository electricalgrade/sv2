#include "sv2_noise.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

/* ---------- I/O: 2-byte big-endian length prefix per frame ---------- */

static int read_full(int fd, void *buf, size_t want) {
    uint8_t *p = (uint8_t*)buf; size_t got = 0;
    while (got < want) {
        ssize_t r = read(fd, p + got, want - got);
        if (r == 0) return -1;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        got += (size_t)r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t*)buf; size_t sent = 0;
    while (sent < len) {
        ssize_t r = write(fd, p + sent, len - sent);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return -1; }
        sent += (size_t)r;
    }
    return 0;
}

static int read_frame(int fd, uint8_t *buf, size_t cap, size_t *out_len) {
    uint8_t hdr[2];
    if (read_full(fd, hdr, 2) != 0) return -1;
    uint16_t len = ((uint16_t)hdr[0] << 8) | (uint16_t)hdr[1];
    if (len == 0 || len > cap) return -2;
    if (read_full(fd, buf, len) != 0) return -3;
    *out_len = len;
    return 0;
}

static int write_frame(int fd, const uint8_t *buf, size_t len) {
    if (len > 0xFFFF) return -1;
    uint8_t hdr[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xFF) };
    if (write_full(fd, hdr, 2) != 0) return -2;
    if (write_full(fd, buf, len) != 0) return -3;
    return 0;
}

/* ----------------------- server ctor / dtor -------------------------- */

static const char *pattern_name(sv2_noise_pattern_t p) {
    return (p == SV2_NOISE_NX)
        ? "Noise_NX_25519_ChaChaPoly_SHA256"
        : "Noise_XX_25519_ChaChaPoly_BLAKE2s";
}

int sv2_noise_server_new2(sv2_noise_server_t **out,
                          sv2_noise_pattern_t pattern,
                          const uint8_t *static_sk,
                          const char *prologue)
{
    if (!out) return -1;
    *out = NULL;

    sv2_noise_server_t *s = (sv2_noise_server_t*)calloc(1, sizeof(*s));
    if (!s) return -2;
    s->pattern = pattern;

    /* Protocol id */
    NoiseProtocolId pid;
    const char *name = pattern_name(pattern);
    int rc = noise_protocol_name_to_id(&pid, name, strlen(name));
    if (rc != NOISE_ERROR_NONE) { free(s); return -3; }

    /* Handshake state (Responder) */
    rc = noise_handshakestate_new_by_id(&s->hs, &pid, NOISE_ROLE_RESPONDER);
    if (rc != NOISE_ERROR_NONE) { free(s); return -4; }

    /* Optional prologue */
    if (prologue && *prologue) {
        rc = noise_handshakestate_set_prologue(s->hs, prologue, strlen(prologue));
        if (rc != NOISE_ERROR_NONE) { sv2_noise_free(s); return -5; }
        strncpy(s->prologue, prologue, sizeof(s->prologue)-1);
    }

    /* Local static keypair */
    NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(s->hs);
    if (!dh) { sv2_noise_free(s); return -6; }
    if (static_sk) {
        rc = noise_dhstate_set_keypair_private(dh, static_sk, 32);
        if (rc != NOISE_ERROR_NONE) { sv2_noise_free(s); return -7; }
        memcpy(s->static_sk, static_sk, 32);
    } else {
        rc = noise_dhstate_generate_keypair(dh);
        if (rc != NOISE_ERROR_NONE) { sv2_noise_free(s); return -8; }
    }
    rc = noise_dhstate_get_public_key(dh, s->static_pk, 32);
    if (rc != NOISE_ERROR_NONE) { sv2_noise_free(s); return -9; }

    /* Start handshake (most libnoise builds have a default RNG internally) */
    rc = noise_handshakestate_start(s->hs);
    if (rc != NOISE_ERROR_NONE) { sv2_noise_free(s); return -10; }

    *out = s;
    return 0;
}

void sv2_noise_free(sv2_noise_server_t *s) {
    if (!s) return;
    if (s->send_cs) noise_cipherstate_free(s->send_cs);
    if (s->recv_cs) noise_cipherstate_free(s->recv_cs);
    if (s->hs)      noise_handshakestate_free(s->hs);
    free(s);
}

int sv2_noise_get_static_public(const sv2_noise_server_t *s, uint8_t out_pk[32]) {
    if (!s || !out_pk) return -1;
    memcpy(out_pk, s->static_pk, 32);
    return 0;
}

/* --------------------------- handshake I/O --------------------------- */

static int hs_write(NoiseHandshakeState *hs, int fd) {
    uint8_t out[65535];
    NoiseBuffer msg = NOISE_BUFFER_INIT(out, sizeof(out));
    uint8_t dummy = 0; NoiseBuffer payload = NOISE_BUFFER_INIT(&dummy, 0);
    int rc = noise_handshakestate_write_message(hs, &msg, &payload);
    if (rc != NOISE_ERROR_NONE) return -1;
    if (write_frame(fd, msg.data, msg.size) != 0) return -2;
    return 0;
}

static int hs_read(NoiseHandshakeState *hs, int fd) {
    uint8_t inbuf[65535]; size_t inlen=0;
    if (read_frame(fd, inbuf, sizeof(inbuf), &inlen) != 0) return -1;
    NoiseBuffer msg = NOISE_BUFFER_INIT(inbuf, inlen);
    uint8_t dummy=0; NoiseBuffer payload = NOISE_BUFFER_INIT(&dummy, 0);
    int rc = noise_handshakestate_read_message(hs, &msg, &payload);
    return (rc == NOISE_ERROR_NONE) ? 0 : -2;
}

int sv2_noise_handshake_fd(sv2_noise_server_t *s, int fd) {
    if (!s || !s->hs) return -1;
    for (;;) {
        int action = noise_handshakestate_get_action(s->hs);
        if (action == NOISE_ACTION_READ_MESSAGE) {
            if (hs_read(s->hs, fd) != 0) return -3;
        } else if (action == NOISE_ACTION_WRITE_MESSAGE) {
            if (hs_write(s->hs, fd) != 0) return -4;
        } else if (action == NOISE_ACTION_SPLIT) {
            int rc = noise_handshakestate_split(s->hs, &s->send_cs, &s->recv_cs);
            if (rc != NOISE_ERROR_NONE) return -5;
            return 0;
        } else if (action == NOISE_ACTION_COMPLETE) {
            return 0;
        } else if (action == NOISE_ACTION_FAILED) {
            return -10;
        } else {
            return -11;
        }
    }
}

/* -------------------------- transport helpers ----------------------- */

int sv2_noise_send_transport(sv2_noise_server_t *s, int fd,
                             const uint8_t *plain, size_t plen)
{
    if (!s || !s->send_cs) return -1;
    if (plen > 65535) return -2;
    uint8_t buf[65535];
    memcpy(buf, plain, plen);
    NoiseBuffer b = NOISE_BUFFER_INIT(buf, plen);
    int rc = noise_cipherstate_encrypt(s->send_cs, &b);
    if (rc != NOISE_ERROR_NONE) return -3;
    return write_frame(fd, b.data, b.size);
}

int sv2_noise_recv_transport(sv2_noise_server_t *s, int fd,
                             uint8_t *out, size_t cap, size_t *outlen)
{
    if (!s || !s->recv_cs || !out || !outlen) return -1;
    uint8_t inbuf[65535]; size_t inlen=0;
    if (read_frame(fd, inbuf, sizeof(inbuf), &inlen) != 0) return -2;
    if (inlen > cap) return -3;
    memcpy(out, inbuf, inlen);
    NoiseBuffer b = NOISE_BUFFER_INIT(out, inlen);
    int rc = noise_cipherstate_decrypt(s->recv_cs, &b);
    if (rc != NOISE_ERROR_NONE) return -4;
    *outlen = b.size;
    return 0;
}
