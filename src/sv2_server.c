#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "sv2_wire.h"
#include "sv2_common.h"
#include "sv2_mining.h"

static void run_server(int port){
  int s = socket(AF_INET, SOCK_STREAM, 0); if(s<0){ perror("socket"); exit(1); }
  int opt=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=INADDR_ANY;
  if(bind(s,(struct sockaddr*)&a,sizeof(a))<0){ perror("bind"); exit(1); }
  if(listen(s,16)<0){ perror("listen"); exit(1); }
  printf("SV2 server listening on %d\n", port);

  while(1){
    int c = accept(s,NULL,NULL); if(c<0){ perror("accept"); continue; }
    uint8_t buf[4096]; size_t n=0;

    // 1) SetupConnection
    if(!sv2_read_len_prefixed(c, buf, sizeof(buf), &n)){ printf("server: read sc failed\n"); close(c); continue; }
    sv2_SetupConnection sc; if(!sv2_dec_setup_connection(buf, n, &sc)){ printf("server: bad SetupConnection\n"); close(c); continue; }
    printf("server: SetupConnection vendor=%s protocol=%u ver=[%u..%u]\n", sc.vendor, sc.protocol, sc.min_version, sc.max_version);

    sv2_SetupConnectionSuccess ok = { .used_version=2, .flags=0 };
    if(!sv2_send_setup_connection_success(c,&ok)){ printf("server: send sc.success failed\n"); close(c); continue; }

    // 2) OpenStandardMiningChannel (we only peek request_id)
    if(!sv2_read_len_prefixed(c, buf, sizeof(buf), &n)){ printf("server: read open chan failed\n"); close(c); continue; }
    sv2_frame_t fr; if(!sv2_parse_frame(buf, n, &fr) || fr.ext!=SV2_EXT_MINING || fr.msg_type!=SV2_MSG_OPEN_STANDARD_MINING_CHAN){ printf("server: expected open std chan\n"); close(c); continue; }
    uint32_t req_id = sv2_r_u32(fr.payload+0);

    // 3) Respond with channel success + target + job
    sv2_OpenStandardMiningChannelSuccess cs = { .request_id=req_id, .channel_id=1, .initial_target_le=0x1d00ffff, .extranonce_prefix_len=4 };
    cs.extranonce_prefix[0]=0xaa; cs.extranonce_prefix[1]=0xbb; cs.extranonce_prefix[2]=0xcc; cs.extranonce_prefix[3]=0xdd;
    if(!sv2_send_open_std_channel_success(c,&cs)){ printf("server: send chan.success failed\n"); close(c); continue; }

    sv2_SetTarget tgt = { .channel_id=1, .new_target_le=0x1d00ffff };
    sv2_send_set_target(c,&tgt);

    sv2_NewMiningJob job = { .channel_id=1, .job_id=42, .version=0x20000000, .ntime_le=0x05f5e100, .nbits_le=0x1d00ffff };
    memset(job.merkle_root, 0x11, 32);
    sv2_send_new_job(c,&job);

    // 4) Expect SubmitSharesStandard → reply Success
    if(!sv2_read_len_prefixed(c, buf, sizeof(buf), &n)){ printf("server: read share failed\n"); close(c); continue; }
    if(!sv2_parse_frame(buf,n,&fr) || fr.ext!=SV2_EXT_MINING_CHAN || fr.msg_type!=SV2_MSG_SUBMIT_SHARES_STANDARD){ printf("server: not a share\n"); close(c); continue; }

    sv2_SubmitSharesSuccess ss = { .channel_id=1, .new_shares=1 };
    sv2_send_submit_success(c,&ss);

    close(c);
  }
}

int main(int argc, char**argv){
  int port = 3333; if(argc>1) port = atoi(argv[1]);
  run_server(port); return 0;
}
