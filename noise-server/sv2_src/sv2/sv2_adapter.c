#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>

#include "sv2_wire.h"
#include "sv2_common.h"
#include "sv2_mining.h"
#include "sv2_adapter.h"
#include <stdlib.h>
#ifdef __linux__
  #include <sys/epoll.h>
#else
  #include <sys/select.h>
  #include <sys/time.h>
#endif

typedef struct {
  int fd;
  uint32_t channel_id;   // 0 until opened
} Sv2Conn;

struct Sv2Server {
  int listen_fd;

#ifdef __linux__
  int epfd;
#endif

  Sv2Callbacks cb;
  void *cb_user;

  Sv2Conn conns[1024];
  size_t  nconns;

  pthread_t thr;
  int running;
};

/* --------- small helpers --------- */

static void conn_close(struct Sv2Server *s, size_t idx){
  Sv2Conn *c = &s->conns[idx];
  if (c->fd >= 0) {
    if (s->cb.on_disconnect) s->cb.on_disconnect(c->fd, s->cb_user);
    close(c->fd);
  }
  // compact
  s->conns[idx] = s->conns[s->nconns - 1];
  s->nconns--;
}

static int conn_send(int fd, const uint8_t *buf, size_t n) {
  return sv2_write_len_prefixed(fd, buf, n);
}

static int send_sc_success(int fd){
  sv2_SetupConnectionSuccess ok = {.used_version=2,.flags=0};
  uint8_t out[256]; ssize_t m = sv2_enc_setup_connection_success(out,sizeof(out),&ok);
  return (m>0) && conn_send(fd,out,(size_t)m);
}

static int send_open_std_success(int fd, uint32_t req_id, uint32_t chan_id){
  sv2_OpenStandardMiningChannelSuccess cs = { .request_id=req_id, .channel_id=chan_id,
                                              .initial_target_le=0x1d00ffff, .extranonce_prefix_len=4 };
  cs.extranonce_prefix[0]=0xaa; cs.extranonce_prefix[1]=0xbb; cs.extranonce_prefix[2]=0xcc; cs.extranonce_prefix[3]=0xdd;
  uint8_t out[256]; ssize_t m = sv2_enc_open_std_channel_success(out, sizeof(out), &cs);
  return (m>0) && conn_send(fd, out, (size_t)m);
}

/* --------- public push APIs --------- */

int sv2_push_set_target(Sv2Server *s, uint32_t channel_id, uint32_t le_target){
  for(size_t i=0;i<s->nconns;i++){
    if(s->conns[i].channel_id == channel_id){
      sv2_SetTarget t = {.channel_id = channel_id, .new_target_le = le_target};
      uint8_t out[64]; ssize_t m = sv2_enc_set_target(out,sizeof(out),&t);
      return (m>0) && conn_send(s->conns[i].fd,out,(size_t)m);
    }
  }
  return 0;
}

int sv2_push_new_job(Sv2Server *s, uint32_t channel_id, uint32_t job_id,
                     const uint8_t merkle_root[32], uint32_t version,
                     uint32_t ntime_le, uint32_t nbits_le){
  for(size_t i=0;i<s->nconns;i++){
    if(s->conns[i].channel_id == channel_id){
      sv2_NewMiningJob j = {.channel_id=channel_id,.job_id=job_id,.version=version,.ntime_le=ntime_le,.nbits_le=nbits_le};
      memcpy(j.merkle_root, merkle_root, 32);
      uint8_t out[128]; ssize_t m = sv2_enc_new_job(out,sizeof(out),&j);
      return (m>0) && conn_send(s->conns[i].fd,out,(size_t)m);
    }
  }
  return 0;
}

int sv2_broadcast_job(Sv2Server *s, uint32_t job_id, const uint8_t merkle_root[32],
                      uint32_t version, uint32_t ntime_le, uint32_t nbits_le){
  int ok=1;
  for(size_t i=0;i<s->nconns;i++){
    uint32_t ch = s->conns[i].channel_id; if(!ch) continue;
    sv2_NewMiningJob j = {.channel_id=ch,.job_id=job_id,.version=version,.ntime_le=ntime_le,.nbits_le=nbits_le};
    memcpy(j.merkle_root, merkle_root, 32);
    uint8_t out[128]; ssize_t m = sv2_enc_new_job(out,sizeof(out),&j);
    ok &= (m>0) && conn_send(s->conns[i].fd,out,(size_t)m);
  }
  return ok;
}

int sv2_ack_share(Sv2Server *s, uint32_t channel_id, uint32_t new_shares){
  for(size_t i=0;i<s->nconns;i++){
    if(s->conns[i].channel_id == channel_id){
      sv2_SubmitSharesSuccess ss = {.channel_id=channel_id,.new_shares=new_shares};
      uint8_t out[64]; ssize_t m = sv2_enc_submit_success(out,sizeof(out),&ss);
      return (m>0) && conn_send(s->conns[i].fd,out,(size_t)m);
    }
  }
  return 0;
}

int sv2_nack_share(Sv2Server *s, uint32_t channel_id, uint32_t err_code, const char *err_msg){
  for(size_t i=0;i<s->nconns;i++){
    if(s->conns[i].channel_id == channel_id){
      sv2_SubmitSharesError se = {.channel_id=channel_id,.error_code=err_code};
      if(err_msg){ strncpy(se.error_msg, err_msg, sizeof(se.error_msg)-1); }
      uint8_t out[256]; ssize_t m = sv2_enc_submit_error(out,sizeof(out),&se);
      return (m>0) && conn_send(s->conns[i].fd,out,(size_t)m);
    }
  }
  return 0;
}

/* --------- event loop thread --------- */

#ifdef __linux__

static void* loop_thr(void *arg){
  Sv2Server *s = (Sv2Server*)arg;
  struct epoll_event ev, events[64];

  while(s->running){
    int nf = epoll_wait(s->epfd, events, 64, 1000);
    for(int i=0;i<nf;i++){
      int fd = events[i].data.fd;
      if(fd == s->listen_fd){
        int c = accept(s->listen_fd,NULL,NULL); if(c<0) continue;
        ev.events = EPOLLIN | EPOLLRDHUP; ev.data.fd = c; epoll_ctl(s->epfd, EPOLL_CTL_ADD, c, &ev);
        if (s->nconns < sizeof(s->conns)/sizeof(s->conns[0])) s->conns[s->nconns++] = (Sv2Conn){ .fd=c, .channel_id=0 };
        if(s->cb.on_connect) s->cb.on_connect(c, s->cb_user);
        continue;
      }

      // read one len-prefixed frame
      uint8_t buf[4096]; size_t n=0;
      if(!sv2_read_len_prefixed(fd, buf, sizeof(buf), &n)){
        for(size_t k=0;k<s->nconns;k++) if(s->conns[k].fd==fd){ conn_close(s,k); break; }
        continue;
      }
      sv2_frame_t fr; if(!sv2_parse_frame(buf,n,&fr)) continue;

      if(fr.ext == SV2_EXT_COMMON && fr.msg_type == SV2_MSG_SETUP_CONNECTION){
        sv2_SetupConnection m; if(!sv2_dec_setup_connection(buf,n,&m)) continue;
        send_sc_success(fd);
      }
      else if(fr.ext == SV2_EXT_MINING && fr.msg_type == SV2_MSG_OPEN_STANDARD_MINING_CHAN){
        uint32_t req_id = sv2_r_u32(fr.payload + 0);
        uint32_t ch_id  = (uint32_t)fd; // demo mapping
        for(size_t k=0;k<s->nconns;k++) if(s->conns[k].fd==fd){ s->conns[k].channel_id = ch_id; break; }
        send_open_std_success(fd, req_id, ch_id);
      }
      else if(fr.ext == SV2_EXT_MINING_CHAN && fr.msg_type == SV2_MSG_SUBMIT_SHARES_STANDARD){
        size_t p=0; uint32_t channel_id = sv2_r_u32(fr.payload+p); p+=4;
        uint32_t job_id    = sv2_r_u32(fr.payload+p); p+=4;
        uint32_t nonce     = sv2_r_u32(fr.payload+p); p+=4;
        const uint8_t *ntime   = fr.payload + p; p+=4;
        const uint8_t *version = fr.payload + p; p+=4;
        if(s->cb.on_share) s->cb.on_share(channel_id, job_id, nonce, ntime, version, s->cb_user);
      }
    }
  }
  return NULL;
}

#else /* non-Linux: select() backend */

static void* loop_thr(void *arg){
  Sv2Server *s = (Sv2Server*)arg;

  while(s->running){
    fd_set rfds; FD_ZERO(&rfds);
    int maxfd = s->listen_fd;
    FD_SET(s->listen_fd, &rfds);
    for(size_t i=0;i<s->nconns;i++){
      if(s->conns[i].fd >= 0){
        FD_SET(s->conns[i].fd, &rfds);
        if(s->conns[i].fd > maxfd) maxfd = s->conns[i].fd;
      }
    }

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    int nf = select(maxfd+1, &rfds, NULL, NULL, &tv);
    if(nf < 0){
      if(errno == EINTR) continue;
      // fatal/select error — slight delay to avoid spin
      usleep(1000);
      continue;
    }
    if(nf == 0) continue; // timeout

    // New connection?
    if(FD_ISSET(s->listen_fd, &rfds)){
      int c = accept(s->listen_fd, NULL, NULL);
      if(c >= 0){
        if (s->nconns < sizeof(s->conns)/sizeof(s->conns[0])) s->conns[s->nconns++] = (Sv2Conn){ .fd=c, .channel_id=0 };
        if(s->cb.on_connect) s->cb.on_connect(c, s->cb_user);
      }
    }

    // Existing connections
    for(size_t i=0;i<s->nconns;){
      int fd = s->conns[i].fd;
      if(fd >= 0 && FD_ISSET(fd, &rfds)){
        uint8_t buf[4096]; size_t n=0;
        if(!sv2_read_len_prefixed(fd, buf, sizeof(buf), &n)){
          conn_close(s, i);
          continue; // do not increment; we compacted
        }
        sv2_frame_t fr; if(!sv2_parse_frame(buf,n,&fr)){ i++; continue; }

        if(fr.ext == SV2_EXT_COMMON && fr.msg_type == SV2_MSG_SETUP_CONNECTION){
          sv2_SetupConnection m; if(!sv2_dec_setup_connection(buf,n,&m)){ i++; continue; }
          send_sc_success(fd);
        }
        else if(fr.ext == SV2_EXT_MINING && fr.msg_type == SV2_MSG_OPEN_STANDARD_MINING_CHAN){
          uint32_t req_id = sv2_r_u32(fr.payload + 0);
          uint32_t ch_id  = (uint32_t)fd; // demo mapping
          s->conns[i].channel_id = ch_id;
          send_open_std_success(fd, req_id, ch_id);
        }
        else if(fr.ext == SV2_EXT_MINING_CHAN && fr.msg_type == SV2_MSG_SUBMIT_SHARES_STANDARD){
          size_t p=0; uint32_t channel_id = sv2_r_u32(fr.payload+p); p+=4;
          uint32_t job_id    = sv2_r_u32(fr.payload+p); p+=4;
          uint32_t nonce     = sv2_r_u32(fr.payload+p); p+=4;
          const uint8_t *ntime   = fr.payload + p; p+=4;
          const uint8_t *version = fr.payload + p; p+=4;
          if(s->cb.on_share) s->cb.on_share(channel_id, job_id, nonce, ntime, version, s->cb_user);
        }
      }
      i++;
    }
  }
  return NULL;
}

#endif /* __linux__ */

/* --------- public start/stop --------- */

Sv2Server* sv2_server_start(const char *bind_ip, int port,
                            const Sv2Callbacks *cb, void *user){
  Sv2Server *s = calloc(1,sizeof(*s));
  if(!s) return NULL;
  if(cb) s->cb = *cb; s->cb_user = user;

  s->listen_fd = socket(AF_INET,SOCK_STREAM,0); if(s->listen_fd<0){ free(s); return NULL; }
  int opt=1; setsockopt(s->listen_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(port);
  a.sin_addr.s_addr = bind_ip? inet_addr(bind_ip) : INADDR_ANY;
  if(bind(s->listen_fd, (struct sockaddr*)&a, sizeof(a))<0){ close(s->listen_fd); free(s); return NULL; }
  if(listen(s->listen_fd, 64)<0){ close(s->listen_fd); free(s); return NULL; }

#ifdef __linux__
  s->epfd = epoll_create1(0); if(s->epfd<0){ close(s->listen_fd); free(s); return NULL; }
  struct epoll_event ev = {0}; ev.events = EPOLLIN; ev.data.fd = s->listen_fd;
  epoll_ctl(s->epfd, EPOLL_CTL_ADD, s->listen_fd, &ev);
#endif

  s->running = 1;
  pthread_create(&s->thr, NULL, loop_thr, s);
  return s;
}

void sv2_server_stop(Sv2Server *s){
  if(!s) return;
  s->running = 0;
  pthread_join(s->thr, NULL);
#ifdef __linux__
  close(s->epfd);
#endif
  close(s->listen_fd);
  for(size_t i=0;i<s->nconns;i++) if(s->conns[i].fd>=0) close(s->conns[i].fd);
  free(s);
}
