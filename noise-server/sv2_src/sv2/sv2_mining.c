// sv2_src/sv2/sv2_common.c
#include "sv2_common.h"
#include <string.h>

static void be16(uint8_t *p, uint16_t v){ p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static void be32(uint8_t *p, uint32_t v){ p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; }
static uint16_t rd16(const uint8_t *p){ return (uint16_t)p[0]<<8 | (uint16_t)p[1]; }
static uint32_t rd32(const uint8_t *p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|((uint32_t)p[3]); }

ssize_t sv2_enc_setup_connection(uint8_t *out, size_t cap, const sv2_SetupConnection *m){
    // protocol(1) + min(2) + max(2) + vendor_len(1) + vendor
    size_t vlen = strnlen(m->vendor, sizeof(m->vendor));
    if (vlen > 255) vlen = 255;
    size_t need = 1 + 2 + 2 + 1 + vlen;
    if (cap < need) return -1;

    out[0] = m->protocol;
    be16(out+1, m->min_version);
    be16(out+3, m->max_version);
    out[5] = (uint8_t)vlen;
    if (vlen) memcpy(out+6, m->vendor, vlen);
    return (ssize_t)need;
}

int sv2_dec_setup_connection(const uint8_t *buf, size_t len, sv2_SetupConnection *out){
    if (len < 6) return 0;
    size_t vlen = buf[5];
    if (6 + vlen > len || vlen >= sizeof(out->vendor)) return 0;

    out->protocol    = buf[0];
    out->min_version = rd16(buf+1);
    out->max_version = rd16(buf+3);
    memcpy(out->vendor, buf+6, vlen);
    out->vendor[vlen] = 0;
    return 1;
}

ssize_t sv2_enc_setup_connection_success(uint8_t *out, size_t cap, const sv2_SetupConnectionSuccess *m){
    if (cap < 6) return -1;
    be16(out+0, m->used_version);
    be32(out+2, m->flags);
    return 6;
}

int sv2_dec_setup_connection_success(const uint8_t *buf, size_t len, sv2_SetupConnectionSuccess *out){
    if (len < 6) return 0;
    out->used_version = rd16(buf+0);
    out->flags        = rd32(buf+2);
    return 1;
}
