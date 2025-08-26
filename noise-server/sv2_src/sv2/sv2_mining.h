#ifndef SV2_MINING_H
#define SV2_MINING_H

#include <stdint.h>
#include <stddef.h>
#include "sv2_wire.h"
#include <sys/types.h> 

#ifdef __cplusplus
extern "C" {
#endif

// --- Messages (demo subset) ---

typedef struct {
  uint32_t request_id;
  uint32_t nominal_hashrate;
  uint32_t max_target_le;
  char     user[256];
} sv2_OpenStandardMiningChannel;

typedef struct {
  uint32_t request_id;
  uint32_t channel_id;
  uint32_t initial_target_le;
  uint8_t  extranonce_prefix[32];
  uint8_t  extranonce_prefix_len;
} sv2_OpenStandardMiningChannelSuccess;

typedef struct { uint32_t channel_id; uint32_t new_target_le; } sv2_SetTarget;

typedef struct {
  uint32_t channel_id;
  uint32_t job_id;
  uint8_t  merkle_root[32];
  uint32_t version;
  uint32_t ntime_le;
  uint32_t nbits_le;
} sv2_NewMiningJob;

typedef struct {
  uint32_t channel_id;
  uint32_t job_id;
  uint32_t nonce;
  uint8_t  ntime[4];
  uint8_t  version[4];
} sv2_SubmitSharesStandard;

typedef struct { uint32_t channel_id; uint32_t new_shares; } sv2_SubmitSharesSuccess;
typedef struct { uint32_t channel_id; uint32_t error_code; char error_msg[256]; } sv2_SubmitSharesError;

// --- encoders (only enc needed for demo path) ---
ssize_t sv2_enc_open_std_channel(uint8_t *out, size_t cap, const sv2_OpenStandardMiningChannel *m);
ssize_t sv2_enc_open_std_channel_success(uint8_t *out, size_t cap, const sv2_OpenStandardMiningChannelSuccess *m);
ssize_t sv2_enc_set_target(uint8_t *out, size_t cap, const sv2_SetTarget *m);
ssize_t sv2_enc_new_job(uint8_t *out, size_t cap, const sv2_NewMiningJob *m);
ssize_t sv2_enc_submit_shares(uint8_t *out, size_t cap, const sv2_SubmitSharesStandard *m);
ssize_t sv2_enc_submit_success(uint8_t *out, size_t cap, const sv2_SubmitSharesSuccess *m);
ssize_t sv2_enc_submit_error(uint8_t *out, size_t cap, const sv2_SubmitSharesError *m);

// --- send helpers ---
int sv2_send_open_std_channel_success(int fd, const sv2_OpenStandardMiningChannelSuccess *m);
int sv2_send_set_target            (int fd, const sv2_SetTarget *m);
int sv2_send_new_job               (int fd, const sv2_NewMiningJob *m);
int sv2_send_submit_success        (int fd, const sv2_SubmitSharesSuccess *m);
int sv2_send_submit_error          (int fd, const sv2_SubmitSharesError *m);

#ifdef __cplusplus
}
#endif
#endif
