// sv2_src/sv2/sv2_mining.c
#include "sv2_mining.h"
#include <string.h>
#include <stdlib.h>

/* =================== endian helpers (big-endian on wire) =================== */

static inline void be16_write(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v);
}
static inline void be32_write(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v);
}
static inline uint16_t be16_read(const uint8_t *p) {
  return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static inline uint32_t be32_read(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* =================== bounds helpers =================== */

static inline int add_size(size_t *acc, size_t add, size_t cap) {
  if (*acc > cap - add) return -1;
  *acc += add;
  return 0;
}

/* =================== OpenStandardMiningChannel =================== */
/* payload:
   u32 request_id
   U256 max_target
   u32 nominal_hash_rate
   u16 user_len
   bytes user[user_len]
*/

ssize_t sv2_enc_open_standard_channel(uint8_t *out, size_t cap,
                                      const sv2_OpenStandardMiningChannel *m) {
  if (!out || !m) return -1;
  size_t need = 0;
  if (add_size(&need, 4 + 32 + 4 + 2 + m->user_len, cap) != 0) return -1;
  size_t off = 0;

  be32_write(out + off, m->request_id); off += 4;
  memcpy(out + off, m->max_target.be, 32); off += 32;
  be32_write(out + off, m->nominal_hash_rate); off += 4;
  be16_write(out + off, m->user_len); off += 2;
  if (m->user_len) memcpy(out + off, m->user, m->user_len), off += m->user_len;

  return (ssize_t)off;
}

int sv2_dec_open_standard_channel(const uint8_t *buf, size_t len,
                                  sv2_OpenStandardMiningChannel *out) {
  if (!buf || !out) return 0;
  if (len < 4 + 32 + 4 + 2) return 0;

  size_t off = 0;
  out->request_id = be32_read(buf + off); off += 4;
  memcpy(out->max_target.be, buf + off, 32); off += 32;
  out->nominal_hash_rate = be32_read(buf + off); off += 4;
  uint16_t ulen = be16_read(buf + off); off += 2;
  if (len < off + ulen) return 0;

  out->user_len = ulen;
  out->user = ulen ? (buf + off) : NULL;
  return 1;
}

/* =================== OpenStandardMiningChannelSuccess =================== */
/* payload:
   u32 request_id
   u32 channel_id
   U256 initial_target
   u8  extranonce_prefix_len
   bytes extranonce_prefix[extranonce_prefix_len]
*/

ssize_t sv2_enc_open_standard_channel_success(
    uint8_t *out, size_t cap, const sv2_OpenStandardMiningChannelSuccess *m) {
  if (!out || !m) return -1;
  if (m->extranonce_prefix_len > 32) return -1;

  size_t need = 4 + 4 + 32 + 1 + m->extranonce_prefix_len;
  if (cap < need) return -1;

  size_t off = 0;
  be32_write(out + off, m->request_id); off += 4;
  be32_write(out + off, m->channel_id); off += 4;
  memcpy(out + off, m->initial_target.be, 32); off += 32;
  out[off++] = m->extranonce_prefix_len;
  if (m->extranonce_prefix_len) {
    memcpy(out + off, m->extranonce_prefix, m->extranonce_prefix_len);
    off += m->extranonce_prefix_len;
  }
  return (ssize_t)off;
}

int sv2_dec_open_standard_channel_success(
    const uint8_t *buf, size_t len, sv2_OpenStandardMiningChannelSuccess *out) {
  if (!buf || !out) return 0;
  if (len < 4 + 4 + 32 + 1) return 0;

  size_t off = 0;
  out->request_id = be32_read(buf + off); off += 4;
  out->channel_id = be32_read(buf + off); off += 4;
  memcpy(out->initial_target.be, buf + off, 32); off += 32;

  uint8_t elen = buf[off++];
  if (elen > 32) return 0;
  if (len < off + elen) return 0;

  out->extranonce_prefix_len = elen;
  memset(out->extranonce_prefix, 0, sizeof(out->extranonce_prefix));
  if (elen) memcpy(out->extranonce_prefix, buf + off, elen);
  return 1;
}

/* =================== NewMiningJob =================== */
/* payload:
   u32 channel_id
   u32 job_id
   u8  is_future_job
   u32 version
   u16 coinbase_tx_prefix_len
   bytes coinbase_tx_prefix[..]
   u16 coinbase_tx_suffix_len
   bytes coinbase_tx_suffix[..]
   u16 merkle_count
   bytes merkle_branch[32] * merkle_count
*/

ssize_t sv2_enc_new_mining_job(uint8_t *out, size_t cap, const sv2_NewMiningJob *m) {
  if (!out || !m) return -1;
  size_t need = 4 + 4 + 1 + 4
              + 2 + m->coinbase_tx_prefix_len
              + 2 + m->coinbase_tx_suffix_len
              + 2 + (size_t)m->merkle_count * 32;
  if (cap < need) return -1;

  size_t off = 0;
  be32_write(out + off, m->channel_id); off += 4;
  be32_write(out + off, m->job_id); off += 4;
  out[off++] = (uint8_t)(m->is_future_job ? 1 : 0);
  be32_write(out + off, m->version); off += 4;

  be16_write(out + off, m->coinbase_tx_prefix_len); off += 2;
  if (m->coinbase_tx_prefix_len) {
    memcpy(out + off, m->coinbase_tx_prefix, m->coinbase_tx_prefix_len);
    off += m->coinbase_tx_prefix_len;
  }
  be16_write(out + off, m->coinbase_tx_suffix_len); off += 2;
  if (m->coinbase_tx_suffix_len) {
    memcpy(out + off, m->coinbase_tx_suffix, m->coinbase_tx_suffix_len);
    off += m->coinbase_tx_suffix_len;
  }

  be16_write(out + off, m->merkle_count); off += 2;
  if (m->merkle_count) {
    size_t mbytes = (size_t)m->merkle_count * 32;
    memcpy(out + off, m->merkle_branch, mbytes);
    off += mbytes;
  }
  return (ssize_t)off;
}

int sv2_dec_new_mining_job(const uint8_t *buf, size_t len, sv2_NewMiningJob *out) {
  if (!buf || !out) return 0;
  if (len < 4 + 4 + 1 + 4 + 2) return 0;

  size_t off = 0;
  out->channel_id = be32_read(buf + off); off += 4;
  out->job_id     = be32_read(buf + off); off += 4;
  out->is_future_job = buf[off++];

  out->version = be32_read(buf + off); off += 4;

  if (len < off + 2) return 0;
  uint16_t pfx_len = be16_read(buf + off); off += 2;
  if (len < off + pfx_len) return 0;
  out->coinbase_tx_prefix_len = pfx_len;
  out->coinbase_tx_prefix = pfx_len ? (buf + off) : NULL;
  off += pfx_len;

  if (len < off + 2) return 0;
  uint16_t sfx_len = be16_read(buf + off); off += 2;
  if (len < off + sfx_len) return 0;
  out->coinbase_tx_suffix_len = sfx_len;
  out->coinbase_tx_suffix = sfx_len ? (buf + off) : NULL;
  off += sfx_len;

  if (len < off + 2) return 0;
  uint16_t mc = be16_read(buf + off); off += 2;
  size_t mbytes = (size_t)mc * 32;
  if (len < off + mbytes) return 0;
  out->merkle_count = mc;
  out->merkle_branch = mbytes ? (buf + off) : NULL;

  return 1;
}

/* =================== SetNewPrevHash =================== */
/* payload:
   u32 channel_id
   u32 job_id
   bytes prev_hash[32]
   u32 min_ntime
   u32 nbits
*/

ssize_t sv2_enc_set_new_prev_hash(uint8_t *out, size_t cap, const sv2_SetNewPrevHash *m) {
  if (!out || !m) return -1;
  size_t need = 4 + 4 + 32 + 4 + 4;
  if (cap < need) return -1;

  size_t off = 0;
  be32_write(out + off, m->channel_id); off += 4;
  be32_write(out + off, m->job_id); off += 4;
  memcpy(out + off, m->prev_hash, 32); off += 32;
  be32_write(out + off, m->min_ntime); off += 4;
  be32_write(out + off, m->nbits); off += 4;
  return (ssize_t)off;
}

int sv2_dec_set_new_prev_hash(const uint8_t *buf, size_t len, sv2_SetNewPrevHash *out) {
  if (!buf || !out) return 0;
  if (len < 4 + 4 + 32 + 4 + 4) return 0;

  size_t off = 0;
  out->channel_id = be32_read(buf + off); off += 4;
  out->job_id     = be32_read(buf + off); off += 4;
  memcpy(out->prev_hash, buf + off, 32); off += 32;
  out->min_ntime = be32_read(buf + off); off += 4;
  out->nbits     = be32_read(buf + off); off += 4;
  return 1;
}

/* =================== SetTarget =================== */
/* payload:
   u32 channel_id
   U256 maximum_target
*/

ssize_t sv2_enc_set_target(uint8_t *out, size_t cap, const sv2_SetTarget *m) {
  if (!out || !m) return -1;
  size_t need = 4 + 32;
  if (cap < need) return -1;

  be32_write(out + 0, m->channel_id);
  memcpy(out + 4, m->maximum_target.be, 32);
  return (ssize_t)36;
}

int sv2_dec_set_target(const uint8_t *buf, size_t len, sv2_SetTarget *out) {
  if (!buf || !out) return 0;
  if (len < 36) return 0;
  out->channel_id = be32_read(buf + 0);
  memcpy(out->maximum_target.be, buf + 4, 32);
  return 1;
}

/* =================== SubmitSharesStandard =================== */
/* payload:
   u32 channel_id
   u32 sequence_number
   u32 job_id
   u32 nonce
   u32 ntime
   u32 version
   u8  extranonce_len
   bytes extranonce[extranonce_len]
   u16 username_len
   bytes username[username_len]
*/

ssize_t sv2_enc_submit_shares_standard(uint8_t *out, size_t cap,
                                       const sv2_SubmitSharesStandard *m) {
  if (!out || !m) return -1;
  size_t need = 4 + 4 + 4 + 4 + 4 + 4 + 1
              + m->extranonce_len
              + 2 + m->username_len;
  if (cap < need) return -1;

  size_t off = 0;
  be32_write(out + off, m->channel_id); off += 4;
  be32_write(out + off, m->sequence_number); off += 4;
  be32_write(out + off, m->job_id); off += 4;
  be32_write(out + off, m->nonce); off += 4;
  be32_write(out + off, m->ntime); off += 4;
  be32_write(out + off, m->version); off += 4;

  out[off++] = m->extranonce_len;
  if (m->extranonce_len) {
    memcpy(out + off, m->extranonce, m->extranonce_len);
    off += m->extranonce_len;
  }

  be16_write(out + off, m->username_len); off += 2;
  if (m->username_len) {
    memcpy(out + off, m->username, m->username_len);
    off += m->username_len;
  }

  return (ssize_t)off;
}

int sv2_dec_submit_shares_standard(const uint8_t *buf, size_t len,
                                   sv2_SubmitSharesStandard *out) {
  if (!buf || !out) return 0;
  if (len < 4*6 + 1 + 2) return 0;

  size_t off = 0;
  out->channel_id      = be32_read(buf + off); off += 4;
  out->sequence_number = be32_read(buf + off); off += 4;
  out->job_id          = be32_read(buf + off); off += 4;
  out->nonce           = be32_read(buf + off); off += 4;
  out->ntime           = be32_read(buf + off); off += 4;
  out->version         = be32_read(buf + off); off += 4;

  uint8_t elen = buf[off++];
  if (len < off + elen + 2) return 0;
  out->extranonce_len = elen;
  out->extranonce = elen ? (buf + off) : NULL;
  off += elen;

  uint16_t ulen = be16_read(buf + off); off += 2;
  if (len < off + ulen) return 0;
  out->username_len = ulen;
  out->username = ulen ? (buf + off) : NULL;

  return 1;
}

/* =================== SubmitSharesSuccess =================== */
/* payload:
   u32 channel_id
   u32 last_sequence_number
   u32 new_submits_accepted_count
   u64 new_shares_sum
*/

ssize_t sv2_enc_submit_shares_success(uint8_t *out, size_t cap,
                                      const sv2_SubmitSharesSuccess *m) {
  if (!out || !m) return -1;
  if (cap < 4 + 4 + 4 + 8) return -1;

  be32_write(out + 0, m->channel_id);
  be32_write(out + 4, m->last_sequence_number);
  be32_write(out + 8, m->new_submits_accepted_count);
  /* u64 big-endian */
  out[12] = (uint8_t)(m->new_shares_sum >> 56);
  out[13] = (uint8_t)(m->new_shares_sum >> 48);
  out[14] = (uint8_t)(m->new_shares_sum >> 40);
  out[15] = (uint8_t)(m->new_shares_sum >> 32);
  out[16] = (uint8_t)(m->new_shares_sum >> 24);
  out[17] = (uint8_t)(m->new_shares_sum >> 16);
  out[18] = (uint8_t)(m->new_shares_sum >> 8);
  out[19] = (uint8_t)(m->new_shares_sum);
  return 20;
}

int sv2_dec_submit_shares_success(const uint8_t *buf, size_t len,
                                  sv2_SubmitSharesSuccess *out) {
  if (!buf || !out) return 0;
  if (len < 20) return 0;

  out->channel_id = be32_read(buf + 0);
  out->last_sequence_number = be32_read(buf + 4);
  out->new_submits_accepted_count = be32_read(buf + 8);
  uint64_t v = 0;
  v |= (uint64_t)buf[12] << 56;
  v |= (uint64_t)buf[13] << 48;
  v |= (uint64_t)buf[14] << 40;
  v |= (uint64_t)buf[15] << 32;
  v |= (uint64_t)buf[16] << 24;
  v |= (uint64_t)buf[17] << 16;
  v |= (uint64_t)buf[18] << 8;
  v |= (uint64_t)buf[19];
  out->new_shares_sum = v;
  return 1;
}

/* =================== SubmitSharesError =================== */
/* payload:
   u32 channel_id
   u32 sequence_number
   u16 error_code_len
   bytes error_code[error_code_len]
*/

ssize_t sv2_enc_submit_shares_error(uint8_t *out, size_t cap,
                                    const sv2_SubmitSharesError *m) {
  if (!out || !m) return -1;
  size_t need = 4 + 4 + 2 + m->error_code_len;
  if (cap < need) return -1;

  size_t off = 0;
  be32_write(out + off, m->channel_id); off += 4;
  be32_write(out + off, m->sequence_number); off += 4;
  be16_write(out + off, m->error_code_len); off += 2;
  if (m->error_code_len) {
    memcpy(out + off, m->error_code, m->error_code_len);
    off += m->error_code_len;
  }
  return (ssize_t)off;
}

int sv2_dec_submit_shares_error(const uint8_t *buf, size_t len,
                                sv2_SubmitSharesError *out) {
  if (!buf || !out) return 0;
  if (len < 4 + 4 + 2) return 0;

  size_t off = 0;
  out->channel_id = be32_read(buf + off); off += 4;
  out->sequence_number = be32_read(buf + off); off += 4;
  uint16_t elen = be16_read(buf + off); off += 2;
  if (len < off + elen) return 0;

  out->error_code_len = elen;
  out->error_code = elen ? (buf + off) : NULL;
  return 1;
}

/* =================== Framed send helpers =================== */

static int send_framed(int fd, uint16_t ext, uint8_t msg_type,
                       const uint8_t *payload, size_t plen) {
  /* build SV2 frame */
  size_t frame_cap = 3 + plen;
  uint8_t *frame = (uint8_t*)malloc(frame_cap);
  if (!frame) return -1;

  ssize_t flen = sv2_build_frame(frame, frame_cap, ext, msg_type, payload, plen);
  if (flen <= 0) { free(frame); return -2; }

  int rc = sv2_write_len_prefixed(fd, frame, (size_t)flen);
  free(frame);
  return rc;
}

int sv2_send_open_standard_channel_success(int fd, const sv2_OpenStandardMiningChannelSuccess *m) {
  size_t plen = 4 + 4 + 32 + 1 + m->extranonce_prefix_len;
  uint8_t *payload = (uint8_t*)malloc(plen);
  if (!payload) return -1;
  ssize_t n = sv2_enc_open_standard_channel_success(payload, plen, m);
  if (n <= 0) { free(payload); return -2; }
  int rc = send_framed(fd, SV2_EXT_MINING, SV2_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, payload, (size_t)n);
  free(payload);
  return rc;
}

int sv2_send_new_mining_job(int fd, const sv2_NewMiningJob *m) {
  size_t plen = 4 + 4 + 1 + 4
              + 2 + m->coinbase_tx_prefix_len
              + 2 + m->coinbase_tx_suffix_len
              + 2 + (size_t)m->merkle_count * 32;
  uint8_t *payload = (uint8_t*)malloc(plen);
  if (!payload) return -1;
  ssize_t n = sv2_enc_new_mining_job(payload, plen, m);
  if (n <= 0) { free(payload); return -2; }
  int rc = send_framed(fd, SV2_EXT_MINING, SV2_MSG_NEW_MINING_JOB, payload, (size_t)n);
  free(payload);
  return rc;
}

int sv2_send_set_new_prev_hash(int fd, const sv2_SetNewPrevHash *m) {
  size_t plen = 4 + 4 + 32 + 4 + 4;
  uint8_t *payload = (uint8_t*)malloc(plen);
  if (!payload) return -1;
  ssize_t n = sv2_enc_set_new_prev_hash(payload, plen, m);
  if (n <= 0) { free(payload); return -2; }
  int rc = send_framed(fd, SV2_EXT_MINING, SV2_MSG_SET_NEW_PREV_HASH, payload, (size_t)n);
  free(payload);
  return rc;
}

int sv2_send_set_target(int fd, const sv2_SetTarget *m) {
  size_t plen = 4 + 32;
  uint8_t *payload = (uint8_t*)malloc(plen);
  if (!payload) return -1;
  ssize_t n = sv2_enc_set_target(payload, plen, m);
  if (n <= 0) { free(payload); return -2; }
  int rc = send_framed(fd, SV2_EXT_MINING, SV2_MSG_SET_TARGET, payload, (size_t)n);
  free(payload);
  return rc;
}

int sv2_send_submit_shares_success(int fd, const sv2_SubmitSharesSuccess *m) {
  size_t plen = 4 + 4 + 4 + 8;
  uint8_t *payload = (uint8_t*)malloc(plen);
  if (!payload) return -1;
  ssize_t n = sv2_enc_submit_shares_success(payload, plen, m);
  if (n <= 0) { free(payload); return -2; }
  int rc = send_framed(fd, SV2_EXT_MINING, SV2_MSG_SUBMIT_SHARES_SUCCESS, payload, (size_t)n);
  free(payload);
  return rc;
}

int sv2_send_submit_shares_error(int fd, const sv2_SubmitSharesError *m) {
  size_t plen = 4 + 4 + 2 + m->error_code_len;
  uint8_t *payload = (uint8_t*)malloc(plen);
  if (!payload) return -1;
  ssize_t n = sv2_enc_submit_shares_error(payload, plen, m);
  if (n <= 0) { free(payload); return -2; }
  int rc = send_framed(fd, SV2_EXT_MINING, SV2_MSG_SUBMIT_SHARES_ERROR, payload, (size_t)n);
  free(payload);
  return rc;
}
