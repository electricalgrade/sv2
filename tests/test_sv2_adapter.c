// cc -O2 -std=c11 -pthread -o test_sv2_adapter tests/test_sv2_adapter.c \
//    src/sv2/sv2_wire.o src/sv2/sv2_common.o src/sv2/sv2_mining.o src/sv2/sv2_adapter.o

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include "sv2_adapter.h"

// simple state to remember the first connection's fd (== channel_id in our demo adapter)
typedef struct {
  Sv2Server *server;
  int first_fd;
} Ctx;

static void on_connect_cb(int fd, void *user){
  Ctx *ctx = (Ctx*)user;
  if (ctx->first_fd == 0) {
    ctx->first_fd = fd;
    fprintf(stderr, "[adapter-test] on_connect: fd=%d (channel_id=%d)\n", fd, fd);
  }
}

static void on_disconnect_cb(int fd, void *user){
  (void)user;
  fprintf(stderr, "[adapter-test] on_disconnect: fd=%d\n", fd);
}

static void on_share_cb(uint32_t channel_id, uint32_t job_id, uint32_t nonce,
                        const uint8_t ntime[4], const uint8_t version[4], void *user)
{
  Ctx *ctx = (Ctx*)user;
  fprintf(stderr, "[adapter-test] on_share: ch=%u job=%u nonce=%u ntime=%02x%02x%02x%02x ver=%02x%02x%02x%02x\n",
          channel_id, job_id, nonce,
          ntime[0],ntime[1],ntime[2],ntime[3],
          version[0],version[1],version[2],version[3]);

  // ACK the share (in real DATUM you'd validate first)
  sv2_ack_share(ctx->server, channel_id, /*new_shares*/1);
}

int main(int argc, char **argv){
  int port = 3333; if(argc>1) port = atoi(argv[1]);

  Ctx ctx = {0};

  Sv2Callbacks cb = {
    .on_share      = on_share_cb,
    .on_connect    = on_connect_cb,
    .on_disconnect = on_disconnect_cb
  };

  ctx.server = sv2_server_start("0.0.0.0", port, &cb, &ctx);
  if(!ctx.server){
    fprintf(stderr, "failed to start sv2 server\n");
    return 1;
  }
  fprintf(stderr, "[adapter-test] server up on %d\n", port);

  // simple loop: once a client connects & opens a channel (adapter sets channel_id=fd),
  // push a target and broadcast a job; the stock sv2_client will then submit a share.
  uint8_t merkle_root[32]; memset(merkle_root, 0x11, sizeof merkle_root);

  for(;;){
    if(ctx.first_fd){
      // push a target to that channel_id (== fd)
      sv2_push_set_target(ctx.server, (uint32_t)ctx.first_fd, 0x1d00ffff);

      // broadcast a job to all channels (includes the one above)
      sv2_broadcast_job(ctx.server, /*job_id*/42, merkle_root,
                        /*version*/0x20000000, /*ntime_le*/0x05f5e100, /*nbits_le*/0x1d00ffff);

      // only do it once for this demo
      ctx.first_fd = -1;
    }
    usleep(100*1000); // 100ms
  }

  // unreachable in this demo
  // sv2_server_stop(ctx.server);
  // return 0;
}
