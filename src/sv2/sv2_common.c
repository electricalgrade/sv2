#include "sv2_common.h"
#include <string.h>

ssize_t sv2_enc_setup_connection(uint8_t *out, size_t cap, const sv2_SetupConnection *m){
  if(cap < 6) return -1; size_t p = 6;
  if(p+2+2+2+4>cap) return -1;
  sv2_w_u16(out+p, m->protocol); p+=2;
  sv2_w_u16(out+p, m->min_version); p+=2;
  sv2_w_u16(out+p, m->max_version); p+=2;
  sv2_w_u32(out+p, m->flags); p+=4;
  if(!sv2_write_str(out,cap,&p,m->endpoint_host)) return -1;
  if(p+2>cap) return -1; sv2_w_u16(out+p, m->endpoint_port); p+=2;
  if(!sv2_write_str(out,cap,&p,m->vendor)) return -1;
  if(!sv2_write_str(out,cap,&p,m->hw_version)) return -1;
  if(!sv2_write_str(out,cap,&p,m->firmware)) return -1;
  if(!sv2_write_str(out,cap,&p,m->device_id)) return -1;
  sv2_write_header(out, SV2_EXT_COMMON, SV2_MSG_SETUP_CONNECTION, (uint32_t)(p-6));
  return (ssize_t)p;
}

int sv2_dec_setup_connection(const uint8_t *buf, size_t n, sv2_SetupConnection *m){
  sv2_frame_t fr; if(!sv2_parse_frame(buf, n, &fr)) return 0;
  if(fr.ext!=SV2_EXT_COMMON || fr.msg_type!=SV2_MSG_SETUP_CONNECTION) return 0;
  size_t p=0;
  if(p+2+2+2+4>fr.len) return 0;
  m->protocol     = sv2_r_u16(fr.payload+p); p+=2;
  m->min_version  = sv2_r_u16(fr.payload+p); p+=2;
  m->max_version  = sv2_r_u16(fr.payload+p); p+=2;
  m->flags        = sv2_r_u32(fr.payload+p); p+=4;
  if(!sv2_read_str(fr.payload,fr.len,&p,m->endpoint_host)) return 0;
  if(p+2>fr.len) return 0; m->endpoint_port = sv2_r_u16(fr.payload+p); p+=2;
  if(!sv2_read_str(fr.payload,fr.len,&p,m->vendor)) return 0;
  if(!sv2_read_str(fr.payload,fr.len,&p,m->hw_version)) return 0;
  if(!sv2_read_str(fr.payload,fr.len,&p,m->firmware)) return 0;
  if(!sv2_read_str(fr.payload,fr.len,&p,m->device_id)) return 0;
  return 1;
}

ssize_t sv2_enc_setup_connection_success(uint8_t *out, size_t cap, const sv2_SetupConnectionSuccess *m){
  if(cap<6) return -1; size_t p=6; if(p+2+4>cap) return -1;
  sv2_w_u16(out+p, m->used_version); p+=2; sv2_w_u32(out+p, m->flags); p+=4;
  sv2_write_header(out, SV2_EXT_COMMON, SV2_MSG_SETUP_CONNECTION_SUCCESS, (uint32_t)(p-6));
  return (ssize_t)p;
}
int sv2_dec_setup_connection_success(const uint8_t *buf, size_t n, sv2_SetupConnectionSuccess *m){
  sv2_frame_t fr; if(!sv2_parse_frame(buf, n, &fr)) return 0;
  if(fr.ext!=SV2_EXT_COMMON || fr.msg_type!=SV2_MSG_SETUP_CONNECTION_SUCCESS) return 0;
  size_t p=0; if(p+2+4>fr.len) return 0;
  m->used_version = sv2_r_u16(fr.payload+p); p+=2;
  m->flags        = sv2_r_u32(fr.payload+p);
  return 1;
}

ssize_t sv2_enc_setup_connection_error(uint8_t *out, size_t cap, const sv2_SetupConnectionError *m){
  if(cap<6) return -1; size_t p=6; if(p+4>cap) return -1;
  sv2_w_u32(out+p, m->error_code); p+=4;
  if(!sv2_write_str(out,cap,&p,m->error_msg)) return -1;
  sv2_write_header(out, SV2_EXT_COMMON, SV2_MSG_SETUP_CONNECTION_ERROR, (uint32_t)(p-6));
  return (ssize_t)p;
}
ssize_t sv2_enc_reconnect(uint8_t *out, size_t cap, const sv2_Reconnect *m){
  if(cap<6) return -1; size_t p=6;
  if(!sv2_write_str(out,cap,&p,m->new_host)) return -1;
  if(p+2+2>cap) return -1; sv2_w_u16(out+p,m->new_port); p+=2; sv2_w_u16(out+p,m->wait_time_sec); p+=2;
  sv2_write_header(out, SV2_EXT_COMMON, SV2_MSG_RECONNECT, (uint32_t)(p-6));
  return (ssize_t)p;
}
ssize_t sv2_enc_channel_endpoint_changed(uint8_t *out, size_t cap, const sv2_ChannelEndpointChanged *m){
  if(cap<6) return -1; size_t p=6;
  if(!sv2_write_str(out,cap,&p,m->new_host)) return -1;
  if(p+2>cap) return -1; sv2_w_u16(out+p,m->new_port); p+=2;
  sv2_write_header(out, SV2_EXT_COMMON, SV2_MSG_CHANNEL_ENDPOINT_CHANGED, (uint32_t)(p-6));
  return (ssize_t)p;
}

// send helpers
int sv2_send_setup_connection_success(int fd, const sv2_SetupConnectionSuccess *m){
  uint8_t out[256]; ssize_t n = sv2_enc_setup_connection_success(out, sizeof(out), m);
  return (n>0) && sv2_write_len_prefixed(fd, out, (size_t)n);
}
int sv2_send_setup_connection_error(int fd, const sv2_SetupConnectionError *m){
  uint8_t out[512]; ssize_t n = sv2_enc_setup_connection_error(out, sizeof(out), m);
  return (n>0) && sv2_write_len_prefixed(fd, out, (size_t)n);
}
int sv2_send_reconnect(int fd, const sv2_Reconnect *m){
  uint8_t out[512]; ssize_t n = sv2_enc_reconnect(out, sizeof(out), m);
  return (n>0) && sv2_write_len_prefixed(fd, out, (size_t)n);
}
int sv2_send_channel_endpoint_changed(int fd, const sv2_ChannelEndpointChanged *m){
  uint8_t out[512]; ssize_t n = sv2_enc_channel_endpoint_changed(out, sizeof(out), m);
  return (n>0) && sv2_write_len_prefixed(fd, out, (size_t)n);
}
