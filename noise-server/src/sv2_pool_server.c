#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "sv2_noise.h"
#include "sv2_wire.h"
#include "sv2_common.h"
#include "mining_dispatch.h"


/* --------------- tiny net helpers --------------- */
static int tcp_listen_bind(const char *host, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = host ? inet_addr(host) : htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) { close(fd); return -2; }
    if (listen(fd, 128) < 0) { close(fd); return -3; }
    return fd;
}

static int accept_one(int lfd) {
    struct sockaddr_in cli; socklen_t cl = sizeof(cli);
    return accept(lfd, (struct sockaddr*)&cli, &cl);
}

static void hex32(const uint8_t *b, char out[65]) {
    static const char d[]="0123456789abcdef";
    for (int i=0;i<32;i++){ out[2*i]=d[b[i]>>4]; out[2*i+1]=d[b[i]&0xF]; }
    out[64]=0;
}

/* --------------- main --------------- */
static void usage(const char *a0) {
    fprintf(stderr,
        "Usage: %s [-l host:port] [--nx] [--prologue STR] [--sk HEX64]\n", a0);
}

int main(int argc, char **argv) {
    char host[64] = "0.0.0.0";
    uint16_t port = 3334;
    int use_nx = 0;
    const char *prologue = "STRATUM/2";
    uint8_t sk[32]; int have_sk = 0;

    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i], "-l") && i+1<argc) {
            const char *hp = argv[++i];
            const char *c = strrchr(hp, ':');
            if (!c) { usage(argv[0]); return 1; }
            size_t hlen = (size_t)(c - hp);
            if (hlen >= sizeof(host)) { usage(argv[0]); return 1; }
            memcpy(host, hp, hlen); host[hlen]=0;
            long p = strtol(c+1, NULL, 10);
            if (p <= 0 || p > 65535) { usage(argv[0]); return 1; }
            port = (uint16_t)p;
        } else if (!strcmp(argv[i], "--ik")) {
            use_nx = 1;
        }else if(!strcmp(argv[i], "--nx")){
            use_nx = 1;
        } else if (!strcmp(argv[i], "--prologue") && i+1<argc) {
            prologue = argv[++i];
        } else if (!strcmp(argv[i], "--sk") && i+1<argc) {
            const char *hex = argv[++i];
            if (strlen(hex) != 64) { fprintf(stderr,"--sk needs 64 hex chars\n"); return 1; }
            for (int j=0;j<32;j++){ unsigned v; if (sscanf(hex+2*j,"%2x",&v)!=1) { fprintf(stderr,"bad --sk\n"); return 1; } sk[j]=(uint8_t)v; }
            have_sk = 1;
        } else {
            usage(argv[0]); return 1;
        }
    }

    int lfd = tcp_listen_bind(host, port);
    if (lfd < 0) { perror("listen"); return 1; }
    printf("[pool] listening on %s:%u (pattern=%s, prologue=\"%s\")\n",
           host, port, use_nx?"NX":"XX", prologue);

    for (;;) {
        int cfd = accept_one(lfd);
        if (cfd < 0) { perror("accept"); continue; }

        sv2_noise_server_t *sv = NULL;
        int rc = sv2_noise_server_new2(&sv,
                                       use_nx? SV2_NOISE_NX : SV2_NOISE_XX,
                                       have_sk? sk : NULL,
                                       prologue);
        if (rc != 0) { fprintf(stderr,"server ctor rc=%d\n", rc); close(cfd); continue; }
        
       
        uint8_t pk[32];
        if (sv2_noise_get_static_public(sv, pk) == 0) {
            char hex[65]; hex32(pk, hex);
            printf("[pool] static pubkey: %s\n", hex);
        }

        rc = sv2_noise_handshake_fd(sv, cfd);
        if (rc != 0) {
            fprintf(stderr,"handshake failed rc=%d\n", rc);
            sv2_noise_free(sv);
            close(cfd);
            continue;
        }

        printf("[pool] handshake complete\n");
        /* Keep connection open; you can now use sv2_noise_{send,recv}_transport() */

        // Read one frame
        uint8_t ibuf[2048]; size_t ilen=0;
        if (sv2_read_len_prefixed(cfd, ibuf, sizeof(ibuf), &ilen) != 0) {
            fprintf(stderr,"[pool] read frame failed\n");
            // cleanup...
        }
        sv2_frame_t f;
        if (sv2_parse_frame(ibuf, ilen, &f) != 1) {
            fprintf(stderr,"[pool] bad SV2 frame\n");
            // cleanup...
        }
        if (f.ext != SV2_EXT_COMMON || f.msg_type != SV2_MSG_SETUP_CONNECTION) {
            fprintf(stderr,"[pool] unexpected msg ext=0x%04x type=0x%02x\n", f.ext, f.msg_type);
            // cleanup...
        }
        // Decode
        sv2_SetupConnection sc;
        if (!sv2_dec_setup_connection(f.payload, f.len, &sc)) {
            fprintf(stderr,"[pool] dec SetupConnection failed\n");
            // cleanup...
        }
        printf("[pool] SetupConnection: protocol=%u min=%u max=%u vendor=\"%s\"\n",
            sc.protocol, sc.min_version, sc.max_version, sc.vendor);

        // Build Success
        sv2_SetupConnectionSuccess ok; memset(&ok, 0, sizeof(ok));
        ok.used_version = 2;
        ok.flags = 0;

        uint8_t payload[64];
        ssize_t plen = sv2_enc_setup_connection_success(payload, sizeof(payload), &ok);
        if (plen <= 0) { fprintf(stderr,"[pool] enc success failed\n"); /* cleanup...*/ }

        uint8_t out[128];
        ssize_t flen = sv2_build_frame(out, sizeof(out),
                                    SV2_EXT_COMMON, SV2_MSG_SETUP_CONNECTION_SUCCESS,
                                    payload, (size_t)plen);
        if (flen <= 0) { fprintf(stderr,"[pool] build frame failed\n"); /* cleanup...*/ }

        if (sv2_write_len_prefixed(cfd, out, (size_t)flen) != 0) {
            fprintf(stderr,"[pool] send success failed\n"); /* cleanup...*/
        }
        printf("[pool] sent SetupConnection.Success (version=%u flags=0x%08x)\n",
       ok.used_version, ok.flags);
       /* enter minimal mining loop (plaintext frames for now) */
        mining_run_after_setup(cfd);
        sv2_noise_free(sv);
        close(cfd);
    }
}
