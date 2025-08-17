#include "sv2_mining.h"
#include <string.h>

ssize_t sv2_enc_open_std_channel(uint8_t *out, size_t cap, const sv2_OpenStandardMiningChannel *m){
  if(cap<6) return -1; size_t p=6;
  if(p+4+4+4>cap) return -1;
  sv2_w_u32(out+p, m->request_id); p+=4;
  sv2_w_u32(out+p, m->nominal_hashrate); p+=4;
  sv2_w_u32(out+p, m->max_target_le); p+=4;
  if(!sv2_write_str(out,cap,&p,m->user)) return -1;
  sv2_write_header(out, SV2_EXT_MINING, SV2_MSG_OPEN_STANDARD_MINING_CHAN, (uint32_t)(p-6));
  return (ssize_t)p;
}

ssize_t sv2_enc_open_std_channel_success(uint8_t *out, size_t cap, const sv2_OpenStandardMiningChannelSuccess *m){
  if(cap<6) return -1; size_t p=6;
  if(p+4+4+4+1>cap) return -1;
  sv2_w_u32(out+p, m->channel_id); p+=4; // first in channel payload
  sv2_w_u32(out+p, m->request_id); p+=4;
  sv2_w_u32(out+p, m->initial_target_le); p+=4;
  out[p++] = m->extranonce_prefix_len;
  if(m->extranonce_prefix_len){
    if(p + m->extranonce_prefix_len > cap) return -1;
    memcpy(out+p, m->extranonce_prefix, m->extranonce_prefix_len); p += m->extranonce_prefix_len;
  }
  sv2_write_header(out, SV2_EXT_MINING_CHAN, SV2_MSG_OPEN_STANDARD_MINING_CHAN_SUCCESS, (uint32_t)(p-6));
  return (ssize_t)p;
}

ssize_t sv2_enc_set_target(uint8_t *out, size_t cap, const sv2_SetTarget *m){
  if(cap<6) return -1; size_t p=6; if(p+4+4>cap) return -1;
  sv2_w_u32(out+p, m->channel_id); p+=4; sv2_w_u32(out+p, m->new_target_le); p+=4;
  sv2_write_header(out, SV2_EXT_MINING_CHAN, SV2_MSG_SET_TARGET, (uint32_t)(p-6)); return (ssize_t)p;
}

ssize_t sv2_enc_new_job(uint8_t *out, size_t cap, const sv2_NewMiningJob *m){
  if(cap<6) return -1; size_t p=6; if(p+4+4+32+4+4+4>cap) return -1;
  sv2_w_u32(out+p, m->channel_id); p+=4;
  sv2_w_u32(out+p, m->job_id); p+=4;
  memcpy(out+p, m->merkle_root, 32); p+=32;
  sv2_w_u32(out+p, m->version); p+=4;
  sv2_w_u32(out+p, m->ntime_le); p+=4;
  sv2_w_u32(out+p, m->nbits_le); p+=4;
  sv2_write_header(out, SV2_EXT_MINING_CHAN, SV2_MSG_NEW_MINING_JOB, (uint32_t)(p-6)); return (ssize_t)p;
}

ssize_t sv2_enc_submit_shares(uint8_t *out, size_t cap, const sv2_SubmitSharesStandard *m){
  if(cap<6) return -1; size_t p=6; if(p+4+4+4+4+4>cap) return -1;
  sv2_w_u32(out+p, m->channel_id); p+=4;
  sv2_w_u32(out+p, m->job_id); p+=4;
  sv2_w_u32(out+p, m->nonce); p+=4;
  memcpy(out+p, m->ntime, 4); p+=4;
  memcpy(out+p, m->version, 4); p+=4;
  sv2_write_header(out, SV2_EXT_MINING_CHAN, SV2_MSG_SUBMIT_SHARES_STANDARD, (uint32_t)(p-6)); return (ssize_t)p;
}

ssize_t sv2_enc_submit_success(uint8_t *out, size_t cap, const sv2_SubmitSharesSuccess *m){
  if(cap<6) return -1; size_t p=6; if(p+4+4>cap) return -1;
  sv2_w_u32(out+p, m->channel_id); p+=4; sv2_w_u32(out+p, m->new_shares); p+=4;
  sv2_write_header(out, SV2_EXT_MINING_CHAN, SV2_MSG_SUBMIT_SHARES_SUCCESS, (uint32_t)(p-6)); return (ssize_t)p;
}
ssize_t sv2_enc_submit_error(uint8_t *out, size_t cap, const sv2_SubmitSharesError *m){
  if(cap<6) return -1; size_t p=6; if(p+4+4>cap) return -1;
  sv2_w_u32(out+p, m->channel_id); p+=4; sv2_w_u32(out+p, m->error_code); p+=4;
  if(!sv2_write_str(out,cap,&p,m->error_msg)) return -1;
  sv2_write_header(out, SV2_EXT_MINING_CHAN, SV2_MSG_SUBMIT_SHARES_ERROR, (uint32_t)(p-6)); return (ssize_t)p;
}

// send helpers
int sv2_send_open_std_channel_success(int fd, const sv2_OpenStandardMiningChannelSuccess *m){
  uint8_t out[512]; ssize_t n = sv2_enc_open_std_channel_success(out, sizeof(out), m);
  return (n>0) && sv2_write_len_prefixed(fd, out, (size_t)n);
}
int sv2_send_set_target(int fd, const sv2_SetTarget *m){
  uint8_t out[64]; ssize_t n = sv2_enc_set_target(out, sizeof(out), m);
  return (n>0) && sv2_write_len_prefixed(fd, out, (size_t)n);
}
int sv2_send_new_job(int fd, const sv2_NewMiningJob *m){
  uint8_t out[128]; ssize_t n = sv2_enc_new_job(out, sizeof(out), m);
  return (n>0) && sv2_write_len_prefixed(fd, out, (size_t)n);
}
int sv2_send_submit_success(int fd, const sv2_SubmitSharesSuccess *m){
  uint8_t out[64]; ssize_t n = sv2_enc_submit_success(out, sizeof(out), m);
  return (n>0) && sv2_write_len_prefixed(fd, out, (size_t)n);
}
int sv2_send_submit_error(int fd, const sv2_SubmitSharesError *m){
  uint8_t out[256]; ssize_t n = sv2_enc_submit_error(out, sizeof(out), m);
  return (n>0) && sv2_write_len_prefixed(fd, out, (size_t)n);
}
