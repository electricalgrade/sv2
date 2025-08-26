// src/noise_client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <noise/protocol/names.h>
#include <noise/protocol/handshakestate.h>
#include <noise/protocol/dhstate.h>
#include <noise/protocol/cipherstate.h>
#include <noise/protocol/buffer.h>
#include <noise/protocol/errors.h>

#include "sv2_wire.h"
#include "sv2_common.h"
#include "sv2_noise.h"

static int send_setupconnection_and_wait_ok(int fd) {
    // Build SetupConnection payload
    sv2_SetupConnection sc;
    memset(&sc, 0, sizeof(sc));
    sc.protocol    = 2;
    sc.min_version = 2;
    sc.max_version = 2;
    strncpy(sc.vendor, "c-noise-client", sizeof(sc.vendor)-1);

    uint8_t payload[256];
    ssize_t plen = sv2_enc_setup_connection(payload, sizeof(payload), &sc);
    if (plen <= 0) { fprintf(stderr,"enc SetupConnection fail\n"); return -1; }

    // Wrap into SV2 frame
    uint8_t frame[512];
    ssize_t flen = sv2_build_frame(frame, sizeof(frame),
                                   SV2_EXT_COMMON, SV2_MSG_SETUP_CONNECTION,
                                   payload, (size_t)plen);
    if (flen <= 0) { fprintf(stderr,"build frame fail\n"); return -1; }

    if (sv2_write_len_prefixed(fd, frame, (size_t)flen) != 0) {
        fprintf(stderr,"write SetupConnection frame fail\n"); return -1;
    }

    // Read response
    uint8_t inbuf[1024]; size_t ilen=0;
    if (sv2_read_len_prefixed(fd, inbuf, sizeof(inbuf), &ilen) != 0) {
        fprintf(stderr,"read response fail\n"); return -1;
    }

    sv2_frame_t f;
    if (sv2_parse_frame(inbuf, ilen, &f) != 1) {
        fprintf(stderr,"parse response frame fail\n"); return -1;
    }
    if (f.ext != SV2_EXT_COMMON || f.msg_type != SV2_MSG_SETUP_CONNECTION_SUCCESS) {
        fprintf(stderr,"unexpected response ext=0x%04x type=0x%02x\n", f.ext, f.msg_type);
        return -1;
    }

    sv2_SetupConnectionSuccess ok;
    if (!sv2_dec_setup_connection_success(f.payload, f.len, &ok)) {
        fprintf(stderr,"decode success fail\n"); return -1;
    }
    printf("[client] SetupConnection.Success used_version=%u flags=0x%08x\n",
           ok.used_version, ok.flags);
    return 0;
}

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
    uint16_t len = ((uint16_t)hdr[0] << 8) | (uint16_t)hdr[1];  // avoid unaligned cast
    if (len == 0 || len > cap) return -2;
    if (read_full(fd, buf, len) != 0) return -3;
    *out_len = len; return 0;
}
static int write_frame(int fd, const uint8_t *buf, size_t len) {
    if (len > 0xFFFF) return -1;
    uint8_t hdr[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xFF) };
    if (write_full(fd, hdr, 2) != 0) return -2;
    if (write_full(fd, buf, len) != 0) return -3;
    return 0;
}
#ifndef NOISE_BUFFER_INIT
static inline NoiseBuffer NB(uint8_t *ptr, size_t len) { NoiseBuffer b; b.data=ptr; b.size=len; b.max_size=len; return b; }
#define NOISE_BUFFER_INIT(ptr,len) NB((uint8_t*)(ptr),(len))
#endif

static int tcp_connect(const char *host, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(host);
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) { close(fd); return -2; }
    return fd;
}

static const char *pattern_name_xx(void) {
    return "Noise_XX_25519_ChaChaPoly_BLAKE2s";
}
static const char *pattern_name_nx(void) {
    return "Noise_NX_25519_ChaChaPoly_SHA256";
}

static int hs_write(NoiseHandshakeState *hs, int fd) {
    uint8_t out[65535];
    NoiseBuffer msg = NOISE_BUFFER_INIT(out, sizeof(out));
    uint8_t dummy=0; NoiseBuffer payload = NOISE_BUFFER_INIT(&dummy, 0);
    int rc = noise_handshakestate_write_message(hs, &msg, &payload);
    if (rc != NOISE_ERROR_NONE) { fprintf(stderr,"[client] write_message rc=%d\n", rc); return -1; }
    if (write_frame(fd, msg.data, msg.size) != 0) return -2;
    return 0;
}
static int hs_read(NoiseHandshakeState *hs, int fd) {
    uint8_t inbuf[65535]; size_t inlen=0;
    if (read_frame(fd, inbuf, sizeof(inbuf), &inlen) != 0) { fprintf(stderr,"[client] read_frame fail\n"); return -1; }
    NoiseBuffer msg = NOISE_BUFFER_INIT(inbuf, inlen);
    uint8_t dummy=0; NoiseBuffer payload = NOISE_BUFFER_INIT(&dummy, 0);
    int rc = noise_handshakestate_read_message(hs, &msg, &payload);
    if (rc != NOISE_ERROR_NONE) { fprintf(stderr,"[client] read_message rc=%d\n", rc); return -2; }
    return 0;
}

static void usage(const char *a0) {
    fprintf(stderr,
        "Usage: %s -l HOST:PORT [--prologue STR]\n"
        "  (This build uses XX only; IK requires a newer noise-c API.)\n", a0);
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    uint16_t port = 3334;
    const char *prologue = "STRATUM/2";
    int use_nx=0;
    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i], "-l") && i+1<argc) {
            const char *hp = argv[++i];
            const char *p = strrchr(hp, ':'); if (!p) { fprintf(stderr,"bad -l\n"); return 1; }
            char buf[64]; size_t hl = (size_t)(p - hp);
            if (hl >= sizeof(buf)) { fprintf(stderr,"host too long\n"); return 1; }
            memcpy(buf, hp, hl); buf[hl]=0; host = strdup(buf);
            long prt = strtol(p+1, NULL, 10);
            if (prt <= 0 || prt > 65535) { fprintf(stderr,"bad port\n"); return 1; }
            port = (uint16_t)prt;
        } else if (!strcmp(argv[i], "--prologue") && i+1<argc) {
            prologue = argv[++i];
        } else if (!strcmp(argv[i], "--ik")) {
            fprintf(stderr,"IK not supported by this libnoise build; use XX.\n");
            return 1; 
        } else if (!strcmp(argv[i], "--nx")) {
            use_nx = 1;
            fprintf(stderr,"Using NX pattern (Noise_NX_25519_ChaChaPoly_SHA256)\n");
        } else if (!strcmp(argv[i], "--xx")) {
            use_nx = 0;
            fprintf(stderr,"Using XX pattern (Noise_XX_25519_ChaChaPoly_BLAKE2s)\n");
        }
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]); return 0;

        }
        else {
            usage(argv[0]); return 1;
        }
    }

    int fd = tcp_connect(host, port);
    if (fd < 0) { perror("connect"); return 1; }

    NoiseProtocolId pid;
    const char *name ;
    if (use_nx == 1) // NX
        name = pattern_name_nx();
    else
        name = pattern_name_xx();
    int rc = noise_protocol_name_to_id(&pid, name, strlen(name));
    if (rc != NOISE_ERROR_NONE) { fprintf(stderr,"proto id fail rc=%d\n", rc); return 1; }

    NoiseHandshakeState *hs = NULL;
    rc = noise_handshakestate_new_by_id(&hs, &pid, NOISE_ROLE_INITIATOR);
    if (rc != NOISE_ERROR_NONE || !hs) { fprintf(stderr,"ctor fail rc=%d\n", rc); return 1; }

    if (prologue && *prologue) {
        rc = noise_handshakestate_set_prologue(hs, prologue, strlen(prologue));
        if (rc != NOISE_ERROR_NONE) { fprintf(stderr,"set prologue rc=%d\n", rc); return 1; }
    }

    
    if (!use_nx) {
        /* XX: initiator has a static keypair */
         NoiseDHState *ldh = noise_handshakestate_get_local_keypair_dh(hs);
         if (!ldh) { fprintf(stderr,"get local dh failed\n"); return 1; }
         rc = noise_dhstate_generate_keypair(ldh);
         if (rc != NOISE_ERROR_NONE) { fprintf(stderr,"gen local static rc=%d\n", rc); return 1; }
    } else {
        /* NX: initiator MUST NOT present a static; do nothing */
        /* Some libnoise builds still require a DH object to exist; but we should not set a static.
           If your build requires it, we could create the object and leave it empty; current API
           via handshakestate is sufficient if we don't touch it. */
     }

    rc = noise_handshakestate_start(hs);
    if (rc != NOISE_ERROR_NONE) { fprintf(stderr,"hs start fail rc=%d\n", rc); return 1; }

    NoiseCipherState *send_cs=NULL, *recv_cs=NULL;
    for (;;) {
        int action = noise_handshakestate_get_action(hs);
        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            if (hs_write(hs, fd) != 0) { fprintf(stderr,"write fail\n"); return 1; }
        } else if (action == NOISE_ACTION_READ_MESSAGE) {
            if (hs_read(hs, fd) != 0)  { fprintf(stderr,"read fail\n"); return 1; }
        } else if (action == NOISE_ACTION_SPLIT) {
            rc = noise_handshakestate_split(hs, &send_cs, &recv_cs);
            if (rc != NOISE_ERROR_NONE) { fprintf(stderr,"split rc=%d\n", rc); return 1; }
            break;
        } else if (action == NOISE_ACTION_COMPLETE) {
            break;
        } else if (action == NOISE_ACTION_FAILED) {
            fprintf(stderr,"action FAILED\n"); return 1;
        } else {
            fprintf(stderr,"unexpected action=%d\n", action); return 1;
        }
    }

    printf("[client] handshake complete\n");
     

    // Do the SV2 handshake:
    if (send_setupconnection_and_wait_ok(fd) != 0) {
        fprintf(stderr,"SV2 SetupConnection exchange failed\n");
        close(fd);
        return 1;
    }

    if (send_cs) noise_cipherstate_free(send_cs);
    if (recv_cs) noise_cipherstate_free(recv_cs);
    noise_handshakestate_free(hs);
    close(fd);
    return 0;
}
