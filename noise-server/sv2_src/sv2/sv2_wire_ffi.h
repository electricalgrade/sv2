#ifndef SV2_WIRE_FFI_H
#define SV2_WIRE_FFI_H

#include <stdint.h>
#include <stddef.h>
// ssize_t
#if defined(_WIN32)
#  include <BaseTsd.h>
   typedef SSIZE_T ssize_t;
#else
#  include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// High-level helpers for Python (ctypes). All return sizes or 1/0 like noted.
// Negative return => parse/encode error.

// ---------- Encode (return number of bytes written, or <0 on error) ----------
ssize_t sv2_enc_setup_connection(uint8_t *out, size_t cap,
                                 const char *id, uint32_t flags);

ssize_t sv2_enc_open_extended_channel(uint8_t *out, size_t cap,
                                      uint32_t req_id, float hashrate_ths);

ssize_t sv2_enc_submit_shares_extended(uint8_t *out, size_t cap,
                                       uint32_t channel_id, uint32_t job_id,
                                       uint32_t nonce, uint32_t ntime, uint32_t version,
                                       const uint8_t *en2, uint16_t en2_len);

// ---------- Decode (return 1 on success, 0 on "not this msg", <0 on error) ----------
int sv2_dec_setup_connection_success(const uint8_t *in, size_t len,
                                     uint16_t *used_version, uint32_t *flags);

int sv2_dec_open_extended_success(const uint8_t *in, size_t len,
                                  uint32_t *channel_id, uint16_t *extranonce2_size);

int sv2_dec_set_new_prev_hash(const uint8_t *in, size_t len,
                              uint32_t *job_id, uint8_t prevhash32_le[32], uint32_t *ntime);

int sv2_dec_new_extended_job(const uint8_t *in, size_t len,
                             uint32_t *job_id, uint32_t *version, uint8_t merkle_root32[32],
                             uint8_t *coinb1_out, uint32_t *coinb1_len,
                             uint8_t *coinb2_out, uint32_t *coinb2_len,
                             uint8_t nbits4[4], uint8_t *clean);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // SV2_WIRE_FFI_H
