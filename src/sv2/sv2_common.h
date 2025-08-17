#ifndef SV2_COMMON_H
#define SV2_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include "sv2_wire.h"
#include <sys/types.h> 

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint16_t protocol;      // 0=Mining, 1=Job Declaration, 2=Template Distribution
  uint16_t min_version;   // usually 2
  uint16_t max_version;   // usually 2
  uint32_t flags;
  char endpoint_host[256];
  uint16_t endpoint_port;
  char vendor[256];
  char hw_version[256];
  char firmware[256];
  char device_id[256];
} sv2_SetupConnection;

typedef struct { uint16_t used_version; uint32_t flags; } sv2_SetupConnectionSuccess;
typedef struct { uint32_t error_code; char error_msg[256]; } sv2_SetupConnectionError;
typedef struct { char new_host[256]; uint16_t new_port; uint16_t wait_time_sec; } sv2_Reconnect;
typedef struct { char new_host[256]; uint16_t new_port; } sv2_ChannelEndpointChanged;

// encode
ssize_t sv2_enc_setup_connection(uint8_t *out, size_t cap, const sv2_SetupConnection *m);
int     sv2_dec_setup_connection(const uint8_t *buf, size_t n, sv2_SetupConnection *m);

ssize_t sv2_enc_setup_connection_success(uint8_t *out, size_t cap, const sv2_SetupConnectionSuccess *m);
int     sv2_dec_setup_connection_success(const uint8_t *buf, size_t n, sv2_SetupConnectionSuccess *m);

ssize_t sv2_enc_setup_connection_error(uint8_t *out, size_t cap, const sv2_SetupConnectionError *m);
ssize_t sv2_enc_reconnect(uint8_t *out, size_t cap, const sv2_Reconnect *m);
ssize_t sv2_enc_channel_endpoint_changed(uint8_t *out, size_t cap, const sv2_ChannelEndpointChanged *m);

// send (len-prefixed I/O)
int sv2_send_setup_connection_success(int fd, const sv2_SetupConnectionSuccess *m);
int sv2_send_setup_connection_error  (int fd, const sv2_SetupConnectionError *m);
int sv2_send_reconnect               (int fd, const sv2_Reconnect *m);
int sv2_send_channel_endpoint_changed(int fd, const sv2_ChannelEndpointChanged *m);

#ifdef __cplusplus
}
#endif
#endif
