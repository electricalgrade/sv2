#include "sv2_wire.h"
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int sv2_is_channel_msg(uint16_t ext){ return (ext & 0x8000) != 0; }

size_t sv2_write_header(uint8_t *out, uint16_t ext, uint8_t msg_type, uint32_t payload_len){
  sv2_w_u16(out, ext); out[2] = msg_type; sv2_u24_write_le(&out[3], payload_len); return 6;
}

int sv2_parse_frame(const uint8_t *buf, size_t n, sv2_frame_t *f){
  if(n < 6) return 0;
  f->ext = sv2_r_u16(buf);
  f->msg_type = buf[2];
  f->len = sv2_u24_read_le(&buf[3]);
  if(6 + f->len != n) return 0;
  f->payload = buf + 6;
  return 1;
}

int sv2_write_str(uint8_t *buf, size_t cap, size_t *pos, const char *s){
  size_t n = s ? strlen(s) : 0; if(n > 255) n = 255;
  if(*pos + 1 + n > cap) return 0;
  buf[(*pos)++] = (uint8_t)n; if(n) memcpy(buf + *pos, s, n); *pos += n; return 1;
}
int sv2_read_str(const uint8_t *buf, size_t cap, size_t *pos, char out[256]){
  if(*pos >= cap) return 0; uint8_t n = buf[(*pos)++]; if(*pos + n > cap) return 0;
  if(n > 0) memcpy(out, buf + *pos, n); out[n] = 0; *pos += n; return 1;
}
int sv2_write_b255(uint8_t *buf, size_t cap, size_t *pos, const uint8_t *data, size_t n){
  if(n > 255) return 0; if(*pos + 1 + n > cap) return 0; buf[(*pos)++] = (uint8_t)n;
  if(n) memcpy(buf + *pos, data, n); *pos += n; return 1;
}
int sv2_read_b255(const uint8_t *buf, size_t cap, size_t *pos, uint8_t *out, size_t *n_out){
  if(*pos >= cap) return 0; uint8_t n = buf[(*pos)++]; if(*pos + n > cap) return 0;
  if(out && n_out && *n_out >= n) memcpy(out, buf + *pos, n);
  *pos += n; if(n_out) *n_out = n; return 1;
}

// ---- TCP helpers ----
int sv2_write_all(int fd, const void *buf, size_t len){
  const uint8_t *p = (const uint8_t*)buf; size_t w = 0;
  while(w < len){ ssize_t r = write(fd, p + w, len - w); if(r <= 0) return 0; w += (size_t)r; }
  return 1;
}
int sv2_read_all(int fd, void *buf, size_t len){
  uint8_t *p = (uint8_t*)buf; size_t rcv = 0;
  while(rcv < len){ ssize_t r = read(fd, p + rcv, len - rcv); if(r <= 0) return 0; rcv += (size_t)r; }
  return 1;
}
int sv2_write_len_prefixed(int fd, const uint8_t *buf, size_t len){
  uint32_t nlen = htonl((uint32_t)len);
  return sv2_write_all(fd, &nlen, 4) && sv2_write_all(fd, buf, len);
}
int sv2_read_len_prefixed(int fd, uint8_t *buf, size_t cap, size_t *out_len){
  uint32_t nlen_net; if(!sv2_read_all(fd, &nlen_net, 4)) return 0;
  uint32_t nlen = ntohl(nlen_net); if(nlen > cap) return 0;
  if(!sv2_read_all(fd, buf, nlen)) return 0; *out_len = nlen; return 1;
}
