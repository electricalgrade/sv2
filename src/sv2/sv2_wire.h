#ifndef SV2_WIRE_H
#define SV2_WIRE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------- Extension types ----------
enum {
  SV2_EXT_COMMON        = 0x0000,
  SV2_EXT_MINING        = 0x0001,
  SV2_EXT_MINING_CHAN   = 0x8001, // MSB=1 => channel-scoped; payload starts with u32 channel_id
};

// ---------- Common message IDs ----------
enum {
  SV2_MSG_SETUP_CONNECTION           = 0x00, // client->server
  SV2_MSG_SETUP_CONNECTION_SUCCESS   = 0x01, // server->client
  SV2_MSG_SETUP_CONNECTION_ERROR     = 0x02, // server->client
  SV2_MSG_CHANNEL_ENDPOINT_CHANGED   = 0x03, // server->client
  SV2_MSG_RECONNECT                  = 0x04  // server->client
};

// ---------- Mining message IDs (subset for demo) ----------
enum {
  SV2_MSG_OPEN_STANDARD_MINING_CHAN          = 0x10, // client->server
  SV2_MSG_OPEN_STANDARD_MINING_CHAN_SUCCESS  = 0x11, // server->client (channel)
  SV2_MSG_OPEN_MINING_CHAN_ERROR             = 0x12, // server->client
  SV2_MSG_SET_TARGET                         = 0x13, // server->client (channel)
  SV2_MSG_NEW_MINING_JOB                     = 0x14, // server->client (channel)
  SV2_MSG_SUBMIT_SHARES_STANDARD             = 0x15, // client->server (channel)
  SV2_MSG_SUBMIT_SHARES_SUCCESS              = 0x16, // server->client (channel)
  SV2_MSG_SUBMIT_SHARES_ERROR                = 0x17  // server->client (channel)
};

// ---------- Frame ----------
typedef struct {
  uint16_t ext;        // extension_type
  uint8_t  msg_type;   // message type
  uint32_t len;        // payload length (U24) promoted to u32
  const uint8_t *payload; // points inside the buffer (after 6-byte header)
} sv2_frame_t;

// ---------- Endian helpers (LE) ----------
static inline void sv2_w_u16(uint8_t *b, uint16_t v){ b[0]=v&0xFF; b[1]=(v>>8)&0xFF; }
static inline void sv2_w_u32(uint8_t *b, uint32_t v){ b[0]=v&0xFF; b[1]=(v>>8)&0xFF; b[2]=(v>>16)&0xFF; b[3]=(v>>24)&0xFF; }
static inline uint16_t sv2_r_u16(const uint8_t *b){ return (uint16_t)b[0] | ((uint16_t)b[1]<<8); }
static inline uint32_t sv2_r_u32(const uint8_t *b){ return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24); }
static inline uint32_t sv2_u24_read_le(const uint8_t b[3]){ return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16); }
static inline void     sv2_u24_write_le(uint8_t b[3], uint32_t v){ b[0]=v&0xFF; b[1]=(v>>8)&0xFF; b[2]=(v>>16)&0xFF; }

int sv2_is_channel_msg(uint16_t ext);

// ---------- Frame header encode/parse ----------
size_t sv2_write_header(uint8_t *out, uint16_t ext, uint8_t msg_type, uint32_t payload_len);
int    sv2_parse_frame(const uint8_t *buf, size_t n, sv2_frame_t *f);

// ---------- Small string/bytes helpers (SV2 STR0_255 / B0_255) ----------
int sv2_write_str(uint8_t *buf, size_t cap, size_t *pos, const char *s);
int sv2_read_str (const uint8_t *buf, size_t cap, size_t *pos, char out[256]);
int sv2_write_b255(uint8_t *buf, size_t cap, size_t *pos, const uint8_t *data, size_t n);
int sv2_read_b255 (const uint8_t *buf, size_t cap, size_t *pos, uint8_t *out, size_t *n_out);

// ---------- TCP helpers (outer 4-byte length prefix for demo I/O) ----------
int sv2_write_len_prefixed(int fd, const uint8_t *buf, size_t len);
int sv2_read_len_prefixed (int fd, uint8_t *buf, size_t cap, size_t *out_len);
int sv2_write_all(int fd, const void *buf, size_t len);
int sv2_read_all (int fd, void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif // SV2_WIRE_H
