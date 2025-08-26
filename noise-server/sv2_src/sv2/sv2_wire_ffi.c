#include "sv2_wire_ffi.h"
#include "sv2_wire.h"

#include <string.h>

#if defined(_WIN32)
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;
#else
  #include <sys/types.h>
#endif

// ---- Extended mining message IDs (shim-local; keep your original enums intact) ----
enum {
  SV2_MSG_OPEN_EXTENDED_MINING_CHAN          = 0x20, // client->server
  SV2_MSG_OPEN_EXTENDED_MINING_CHAN_SUCCESS  = 0x21, // server->client (returns channel_id, extranonce size)
  SV2_MSG_SET_NEW_PREV_HASH                  = 0x22, // server->client
  SV2_MSG_NEW_EXTENDED_MINING_JOB            = 0x23, // server->client
  SV2_MSG_SUBMIT_SHARES_EXTENDED             = 0x24, // client->server (channel-scoped)
};

// ---------- Encode ----------

ssize_t sv2_enc_setup_connection(uint8_t *out, size_t cap,
                                 const char *id, uint32_t flags)
{
  size_t id_len = id ? strlen(id) : 0;
  // payload = STR0_255(id) + u32 flags
  size_t payload_len = 1 + id_len + 4;
  if (cap < 6 + payload_len) return -1;

  size_t hdr = sv2_write_header(out, SV2_EXT_COMMON, SV2_MSG_SETUP_CONNECTION, (uint32_t)payload_len);
  size_t pos = hdr;
  size_t ppos = 0;
  if (!sv2_write_str(out + pos, cap - pos, &ppos, id ? id : "")) return -2;
  sv2_w_u32(out + pos + ppos, flags); ppos += 4;
  return (ssize_t)(pos + ppos);
}

ssize_t sv2_enc_open_extended_channel(uint8_t *out, size_t cap,
                                      uint32_t req_id, float hashrate_ths)
{
  // payload = u32 req_id + f32 hashrate_ths (LE)
  size_t payload_len = 4 + 4;
  if (cap < 6 + payload_len) return -1;

  size_t hdr = sv2_write_header(out, SV2_EXT_MINING, SV2_MSG_OPEN_EXTENDED_MINING_CHAN, (uint32_t)payload_len);
  sv2_w_u32(out + hdr, req_id);
  // write float LE safely
  union { float f; uint32_t u; } u = { .f = hashrate_ths };
  sv2_w_u32(out + hdr + 4, u.u);
  return (ssize_t)(hdr + payload_len);
}

ssize_t sv2_enc_submit_shares_extended(uint8_t *out, size_t cap,
                                       uint32_t channel_id, uint32_t job_id,
                                       uint32_t nonce, uint32_t ntime, uint32_t version,
                                       const uint8_t *en2, uint16_t en2_len)
{
  // channel-scoped: payload starts with u32 channel_id
  // payload = u32 channel_id + u32 job_id + u32 nonce + u32 ntime + u32 version + B0_255 extranonce2
  size_t payload_len = 4 + 4 + 4 + 4 + 4 + 1 + en2_len;
  if (en2_len > 255) return -1;
  if (cap < 6 + payload_len) return -1;

  size_t hdr = sv2_write_header(out, SV2_EXT_MINING_CHAN, SV2_MSG_SUBMIT_SHARES_EXTENDED, (uint32_t)payload_len);
  size_t pos = hdr;
  sv2_w_u32(out + pos, channel_id); pos += 4;
  sv2_w_u32(out + pos, job_id); pos += 4;
  sv2_w_u32(out + pos, nonce); pos += 4;
  sv2_w_u32(out + pos, ntime); pos += 4;
  sv2_w_u32(out + pos, version); pos += 4;

  size_t ppos = 0;
  if (!sv2_write_b255(out + pos, cap - pos, &ppos, en2, en2_len)) return -2;
  pos += ppos;

  return (ssize_t)pos;
}

// ---------- Decode ----------

int sv2_dec_setup_connection_success(const uint8_t *in, size_t len,
                                     uint16_t *used_version, uint32_t *flags)
{
  sv2_frame_t f;
  if (!sv2_parse_frame(in, len, &f)) return -1;
  if (f.ext != SV2_EXT_COMMON || f.msg_type != SV2_MSG_SETUP_CONNECTION_SUCCESS) return 0;

  size_t pos = 0;
  if (f.len < 2 + 4) return -1;
  if (used_version) *used_version = sv2_r_u16(f.payload + pos);
  pos += 2;
  if (flags) *flags = sv2_r_u32(f.payload + pos);
  pos += 4;
  (void)pos;
  return 1;
}

int sv2_dec_open_extended_success(const uint8_t *in, size_t len,
                                  uint32_t *channel_id, uint16_t *extranonce2_size)
{
  sv2_frame_t f;
  if (!sv2_parse_frame(in, len, &f)) return -1;
  if (f.ext != SV2_EXT_MINING || f.msg_type != SV2_MSG_OPEN_EXTENDED_MINING_CHAN_SUCCESS) return 0;

  size_t pos = 0;
  if (f.len < 4 + 2) return -1;
  if (channel_id) *channel_id = sv2_r_u32(f.payload + pos);
  pos += 4;
  if (extranonce2_size) *extranonce2_size = sv2_r_u16(f.payload + pos);
  pos += 2;
  (void)pos;
  return 1;
}

int sv2_dec_set_new_prev_hash(const uint8_t *in, size_t len,
                              uint32_t *job_id, uint8_t prevhash32_le[32], uint32_t *ntime)
{
  sv2_frame_t f;
  if (!sv2_parse_frame(in, len, &f)) return -1;
  if (f.ext != SV2_EXT_MINING || f.msg_type != SV2_MSG_SET_NEW_PREV_HASH) return 0;

  size_t need = 4 + 32 + 4;
  if (f.len < need) return -1;

  size_t pos = 0;
  if (job_id) *job_id = sv2_r_u32(f.payload + pos);
  pos += 4;
  if (prevhash32_le) memcpy(prevhash32_le, f.payload + pos, 32);
  pos += 32;
  if (ntime) *ntime = sv2_r_u32(f.payload + pos);
  pos += 4;

  return 1;
}

int sv2_dec_new_extended_job(const uint8_t *in, size_t len,
                             uint32_t *job_id, uint32_t *version, uint8_t merkle_root32[32],
                             uint8_t *coinb1_out, uint32_t *coinb1_len,
                             uint8_t *coinb2_out, uint32_t *coinb2_len,
                             uint8_t nbits4[4], uint8_t *clean)
{
  sv2_frame_t f;
  if (!sv2_parse_frame(in, len, &f)) return -1;
  if (f.ext != SV2_EXT_MINING || f.msg_type != SV2_MSG_NEW_EXTENDED_MINING_JOB) return 0;

  size_t pos = 0;
  if (f.len < 4 + 4 + 32 + 4) return -1; // job_id + version + merkle + nbits (we’ll read B255s with helpers)

  if (job_id) *job_id = sv2_r_u32(f.payload + pos); pos += 4;
  if (version) *version = sv2_r_u32(f.payload + pos); pos += 4;

  if (merkle_root32) memcpy(merkle_root32, f.payload + pos, 32);
  pos += 32;

  // coinb1 B0_255
  {
    size_t got = 0;
    if (!sv2_read_b255(f.payload + pos, f.len - pos, &pos, coinb1_out, &got)) return -1;
    if (coinb1_len) *coinb1_len = (uint32_t)got;
  }

  // coinb2 B0_255
  {
    size_t got = 0;
    if (!sv2_read_b255(f.payload + pos, f.len - pos, &pos, coinb2_out, &got)) return -1;
    if (coinb2_len) *coinb2_len = (uint32_t)got;
  }

  if (pos + 4 + 1 > f.len) return -1;
  if (nbits4) memcpy(nbits4, f.payload + pos, 4);
  pos += 4;

  if (clean) *clean = f.payload[pos];
  pos += 1;

  return 1;
}
