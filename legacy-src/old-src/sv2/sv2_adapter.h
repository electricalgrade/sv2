#pragma once
#include <stdint.h>

typedef struct Sv2Server Sv2Server;

// App (DATUM) → SV2
typedef struct {
  // called when a miner submits a share
  void (*on_share)(uint32_t channel_id, uint32_t job_id,
                   uint32_t nonce, const uint8_t ntime[4], const uint8_t version[4],
                   void *user);
  // optional: connection lifecycle
  void (*on_connect)(int fd, void *user);
  void (*on_disconnect)(int fd, void *user);
} Sv2Callbacks;

Sv2Server* sv2_server_start(const char *bind_ip, int port,
                            const Sv2Callbacks *cb, void *user);
void       sv2_server_stop(Sv2Server *s);

// DATUM pushes new jobs/targets to miners (per channel)
int sv2_push_set_target(Sv2Server *s, uint32_t channel_id, uint32_t le_target);
int sv2_push_new_job   (Sv2Server *s, uint32_t channel_id,
                        uint32_t job_id, const uint8_t merkle_root[32],
                        uint32_t version, uint32_t ntime_le, uint32_t nbits_le);

// (optional) accept a prebuilt job broadcast to all channels
int sv2_broadcast_job  (Sv2Server *s, uint32_t job_id,
                        const uint8_t merkle_root[32], uint32_t version,
                        uint32_t ntime_le, uint32_t nbits_le);

// When DATUM validates a share:
int sv2_ack_share      (Sv2Server *s, uint32_t channel_id, uint32_t new_shares);
int sv2_nack_share     (Sv2Server *s, uint32_t channel_id, uint32_t err_code, const char *err_msg);
