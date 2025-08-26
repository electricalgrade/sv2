#ifndef SV2_NOISE_H
#define SV2_NOISE_H

#include <stdint.h>
#include <stddef.h>

#include <noise/protocol/names.h>
#include <noise/protocol/handshakestate.h>
#include <noise/protocol/dhstate.h>
#include <noise/protocol/cipherstate.h>
#include <noise/protocol/buffer.h>
#include <noise/protocol/errors.h>

/* Fallback for older libnoise that may not define NOISE_BUFFER_INIT */
#ifndef NOISE_BUFFER_INIT
static inline NoiseBuffer SV2_NOISE_BUFFER_INIT_(uint8_t *ptr, size_t len) {
    NoiseBuffer b; b.data = ptr; b.size = len; b.max_size = len; return b;
}
#define NOISE_BUFFER_INIT(ptr, len) SV2_NOISE_BUFFER_INIT_((uint8_t*)(ptr), (len))
#endif

typedef enum {
    SV2_NOISE_XX = 0,
    SV2_NOISE_NX = 1
} sv2_noise_pattern_t;

static int need_local_static(int pattern, int role) {
    if (pattern == SV2_NOISE_XX)
        return 1; // XX: both sides have s
    if (pattern == SV2_NOISE_NX)
        return (role == NOISE_ROLE_RESPONDER); // NX: only responder has s
    return 0;
}
typedef struct sv2_noise_server_s {
    NoiseHandshakeState *hs;
    NoiseCipherState    *send_cs;
    NoiseCipherState    *recv_cs;
    sv2_noise_pattern_t  pattern;
    uint8_t              static_sk[32];
    uint8_t              static_pk[32];
    char                 prologue[128]; /* optional; 0-terminated */
} sv2_noise_server_t;

/* pattern: SV2_NOISE_XX or SV2_NOISE_IK
   static_sk: 32 bytes if non-NULL; if NULL we generate one
   prologue: optional string (may be NULL) */
int  sv2_noise_server_new2(sv2_noise_server_t **out,
                           sv2_noise_pattern_t pattern,
                           const uint8_t *static_sk,
                           const char *prologue);

int  sv2_noise_handshake_fd(sv2_noise_server_t *s, int fd);

int  sv2_noise_get_static_public(const sv2_noise_server_t *s, uint8_t out_pk[32]);

int  sv2_noise_send_transport(sv2_noise_server_t *s, int fd,
                              const uint8_t *plain, size_t plen);
int  sv2_noise_recv_transport(sv2_noise_server_t *s, int fd,
                              uint8_t *out, size_t cap, size_t *outlen);

void sv2_noise_free(sv2_noise_server_t *s);

#endif /* SV2_NOISE_H */
