#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "sv2_wire.h"
#include "sv2_common.h"
#include "sv2_mining.h"

static int run_client(const char *host, int port){
  int fd = socket(AF_INET, SOCK_STREAM, 0); if(fd<0){ perror("socket"); return 1; }
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(port);
  if(inet_pton(AF_INET, host, &a.sin_addr)<=0){ perror("inet_pton"); close(fd); return 1; }
  if(connect(fd,(struct sockaddr*)&a,sizeof(a))<0){ perror("connect"); close(fd); return 1; }

  // 1) SetupConnection
  sv2_SetupConnection sc={0};
  sc.protocol=0; sc.min_version=2; sc.max_version=2; sc.flags=0; sc.endpoint_port=0;
  strcpy(sc.endpoint_host,""); strcpy(sc.vendor,"DemoClient"); strcpy(sc.hw_version,"v0"); strcpy(sc.firmware,"sv2"); strcpy(sc.device_id,"miner123");
  uint8_t out[4096]; ssize_t outlen = sv2_enc_setup_connection(out,sizeof(out),&sc);
  if(outlen<0 || !sv2_write_len_prefixed(fd,out,(size_t)outlen)){ printf("client: send SetupConnection failed\n"); close(fd); return 1; }
  printf("client: sent SetupConnection\n");

  // read success
  uint8_t buf[4096]; size_t n=0; if(!sv2_read_len_prefixed(fd,buf,sizeof(buf),&n)){ printf("client: read sc.success failed\n"); close(fd); return 1; }
  sv2_SetupConnectionSuccess ok; if(!sv2_dec_setup_connection_success(buf,n,&ok)){ printf("client: parse sc.success failed\n"); close(fd); return 1; }
  printf("client: SetupConnection.Success used_version=%u flags=0x%x\n", ok.used_version, ok.flags);

  // 2) open standard channel
  sv2_OpenStandardMiningChannel open = { .request_id=7, .nominal_hashrate=1000000, .max_target_le=0x1d00ffff };
  strcpy(open.user,"demo.user");
  outlen = sv2_enc_open_std_channel(out,sizeof(out),&open);
  if(outlen<0 || !sv2_write_len_prefixed(fd,out,(size_t)outlen)){ printf("client: send open channel failed\n"); close(fd); return 1; }

  // read channel success
  if(!sv2_read_len_prefixed(fd,buf,sizeof(buf),&n)){ printf("client: read chan.success failed\n"); close(fd); return 1; }
  sv2_frame_t fr; if(!sv2_parse_frame(buf,n,&fr) || fr.ext!=SV2_EXT_MINING_CHAN || fr.msg_type!=SV2_MSG_OPEN_STANDARD_MINING_CHAN_SUCCESS){ printf("client: bad chan.success\n"); close(fd); return 1; }
  uint32_t channel_id = sv2_r_u32(fr.payload+0);
  printf("client: channel opened id=%u\n", channel_id);

  // read SetTarget
  if(!sv2_read_len_prefixed(fd,buf,sizeof(buf),&n)){ printf("client: read set_target failed\n"); close(fd); return 1; }
  // read NewMiningJob
  if(!sv2_read_len_prefixed(fd,buf,sizeof(buf),&n)){ printf("client: read new_job failed\n"); close(fd); return 1; }

  // 3) SubmitSharesStandard
  sv2_SubmitSharesStandard sh = { .channel_id=channel_id, .job_id=42, .nonce=1 };
  sh.ntime[0]=0x00; sh.ntime[1]=0x10; sh.ntime[2]=0x5e; sh.ntime[3]=0x0f;
  sh.version[0]=0x00; sh.version[1]=0x00; sh.version[2]=0x00; sh.version[3]=0x20;
  outlen = sv2_enc_submit_shares(out,sizeof(out),&sh);
  if(outlen<0 || !sv2_write_len_prefixed(fd,out,(size_t)outlen)){ printf("client: send share failed\n"); close(fd); return 1; }

  // read SubmitShares.Success
  if(!sv2_read_len_prefixed(fd,buf,sizeof(buf),&n)){ printf("client: read share.resp failed\n"); close(fd); return 1; }
  if(!sv2_parse_frame(buf,n,&fr) || fr.ext!=SV2_EXT_MINING_CHAN || fr.msg_type!=SV2_MSG_SUBMIT_SHARES_SUCCESS){ printf("client: share not accepted\n"); close(fd); return 1; }
  printf("client: share accepted\n");

  close(fd); return 0;
}

int main(int argc, char**argv){
  if(argc < 3){ fprintf(stderr,"Usage: %s host port\n", argv[0]); return 1; }
  return run_client(argv[1], atoi(argv[2]));
}
