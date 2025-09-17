#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>   // ssize_t
#include "sv2_wire.h"    // framing helpers

#ifdef __cplusplus
extern "C" {
#endif

/* ========= Extension & Message IDs ========= */

/* If you prefer to keep everything under COMMON, you can change this to 0x0000.
   Otherwise define a dedicated MINING extension: */
#ifndef SV2_EXT_MINING
#define SV2_EXT_MINING 0x0001
#endif

enum {
  SV2_MSG_OPEN_STANDARD_MINING_CHANNEL         = 0x10, /* C->S */
  SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS = 0x11, /* S->C */
  SV2_MSG_NEW_MINING_JOB                       = 0x20, /* S->C */
  SV2_MSG_SET_NEW_PREV_HASH                    = 0x21, /* S->C */
  SV2_MSG_SET_TARGET                           = 0x22, /* S->C */
  SV2_MSG_SUBMIT_SHARES_STANDARD               = 0x30, /* C->S */
  SV2_MSG_SUBMIT_SHARES_SUCCESS                = 0x31, /* S->C */
  SV2_MSG_SUBMIT_SHARES_ERROR                  = 0x32  /* S->C */
};

/* ========= Common fixed-size types ========= */

typedef struct { uint8_t be[32]; } sv2_U256; /* big-endian 256-bit */

/* ========= Message structs (wire-order, BE for multibyte ints) ========= */

/* C->S */
typedef struct {
  uint32_t request_id;          /* BE on wire */
  sv2_U256 max_target;          /* 32 bytes, BE */
  uint32_t nominal_hash_rate;   /* BE on wire */
  /* flexible: user (<= 65535) carried separately in encoder/decoder */
  /* in-memory convenience: */
  const uint8_t *user;          /* not owned; length in user_len */
  uint16_t user_len;
} sv2_OpenStandardMiningChannel;

/* S->C */
typedef struct {
  uint32_t request_id;          /* echo */
  uint32_t channel_id;
  sv2_U256 initial_target;      /* 32 bytes, BE */
  uint8_t  extranonce_prefix_len; /* <= 32 */
  uint8_t  extranonce_prefix[32];
} sv2_OpenStandardMiningChannelSuccess;

/* S->C */
typedef struct {
  uint32_t channel_id;
  uint32_t job_id;
  uint8_t  is_future_job;       /* 0 or 1 */
  uint32_t version;
  /* coinbase parts */
  const uint8_t *coinbase_tx_prefix; uint16_t coinbase_tx_prefix_len;
  const uint8_t *coinbase_tx_suffix; uint16_t coinbase_tx_suffix_len;
  /* merkle path (excludes coinbase) */
  const uint8_t *merkle_branch; uint16_t merkle_count; /* merkle_branch = 32*merkle_count bytes */
} sv2_NewMiningJob;

/* S->C */
typedef struct {
  uint32_t channel_id;
  uint32_t job_id;
  uint8_t  prev_hash[32];       /* raw 32 bytes */
  uint32_t min_ntime;
  uint32_t nbits;
} sv2_SetNewPrevHash;

/* S->C */
typedef struct {
  uint32_t channel_id;
  sv2_U256 maximum_target;
} sv2_SetTarget;

/* C->S */
typedef struct {
  uint32_t channel_id;
  uint32_t sequence_number;
  uint32_t job_id;
  uint32_t nonce;
  uint32_t ntime;
  uint32_t version;
  uint8_t  extranonce_len;
  const uint8_t *extranonce;    /* length = extranonce_len */
  const uint8_t *username;      /* optional; length in username_len */
  uint16_t username_len;
} sv2_SubmitSharesStandard;

/* S->C */
typedef struct {
  uint32_t channel_id;
  uint32_t last_sequence_number;
  uint32_t new_submits_accepted_count;
  uint64_t new_shares_sum;
} sv2_SubmitSharesSuccess;

/* S->C */
typedef struct {
  uint32_t channel_id;
  uint32_t sequence_number;
  const uint8_t *error_code;    /* ASCII */
  uint16_t error_code_len;
} sv2_SubmitSharesError;

/* ========= Codec API (payload enc/dec only; no framing here) ========= */

/* OpenStandardMiningChannel */
ssize_t sv2_enc_open_standard_channel(uint8_t *out, size_t cap,
                                      const sv2_OpenStandardMiningChannel *m);
int     sv2_dec_open_standard_channel(const uint8_t *buf, size_t len,
                                      sv2_OpenStandardMiningChannel *out);

/* OpenStandardMiningChannelSuccess */
ssize_t sv2_enc_open_standard_channel_success(uint8_t *out, size_t cap,
                                              const sv2_OpenStandardMiningChannelSuccess *m);
int     sv2_dec_open_standard_channel_success(const uint8_t *buf, size_t len,
                                              sv2_OpenStandardMiningChannelSuccess *out);

/* NewMiningJob */
ssize_t sv2_enc_new_mining_job(uint8_t *out, size_t cap, const sv2_NewMiningJob *m);
int     sv2_dec_new_mining_job(const uint8_t *buf, size_t len, sv2_NewMiningJob *out);

/* SetNewPrevHash */
ssize_t sv2_enc_set_new_prev_hash(uint8_t *out, size_t cap, const sv2_SetNewPrevHash *m);
int     sv2_dec_set_new_prev_hash(const uint8_t *buf, size_t len, sv2_SetNewPrevHash *out);

/* SetTarget */
ssize_t sv2_enc_set_target(uint8_t *out, size_t cap, const sv2_SetTarget *m);
int     sv2_dec_set_target(const uint8_t *buf, size_t len, sv2_SetTarget *out);

/* SubmitSharesStandard */
ssize_t sv2_enc_submit_shares_standard(uint8_t *out, size_t cap,
                                       const sv2_SubmitSharesStandard *m);
int     sv2_dec_submit_shares_standard(const uint8_t *buf, size_t len,
                                       sv2_SubmitSharesStandard *out);

/* SubmitSharesSuccess */
ssize_t sv2_enc_submit_shares_success(uint8_t *out, size_t cap,
                                      const sv2_SubmitSharesSuccess *m);
int     sv2_dec_submit_shares_success(const uint8_t *buf, size_t len,
                                      sv2_SubmitSharesSuccess *out);

/* SubmitSharesError */
ssize_t sv2_enc_submit_shares_error(uint8_t *out, size_t cap,
                                    const sv2_SubmitSharesError *m);
int     sv2_dec_submit_shares_error(const uint8_t *buf, size_t len,
                                    sv2_SubmitSharesError *out);

/* ========= Framed send helpers (build SV2 frame + write len-prefix) ========= */
/* These *only* do cleartext TCP framing. If/when you switch to transport
   encryption with Noise cipherstates, replace write with your encrypted path. */

int sv2_send_open_standard_channel_success(int fd, const sv2_OpenStandardMiningChannelSuccess *m);
int sv2_send_new_mining_job(int fd, const sv2_NewMiningJob *m);
int sv2_send_set_new_prev_hash(int fd, const sv2_SetNewPrevHash *m);
int sv2_send_set_target(int fd, const sv2_SetTarget *m);
int sv2_send_submit_shares_success(int fd, const sv2_SubmitSharesSuccess *m);
int sv2_send_submit_shares_error(int fd, const sv2_SubmitSharesError *m);

#ifdef __cplusplus
}
#endif
