// src/mining_dispatch.c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "sv2_wire.h"
#include "sv2_mining.h"

// ---- tiny helpers --------------------------------------------------

static inline uint32_t now_ntime_le(void) {
    return (uint32_t)time(NULL);
}

static void zero32(uint8_t x[32]) { memset(x, 0, 32); }

// ---- per-message handlers ------------------------------------------

static int on_open_standard_channel(int fd, const sv2_OpenStandardMiningChannel *m) {
    fprintf(stdout,
            "[mining] OpenStandardMiningChannel: req=%u user=\"%.*s\" hashrate=%u\n",
            m->request_id,
            (int)m->user_len, (const char*)m->user,
            m->nominal_hash_rate);

    // 1) Success
    sv2_OpenStandardMiningChannelSuccess ok;
    memset(&ok, 0, sizeof(ok));
    ok.request_id = m->request_id;
    ok.channel_id = 1;  // static for demo
    ok.initial_target = m->max_target;  // echo the client's requested max as initial
    ok.extranonce_prefix_len = 4;
    ok.extranonce_prefix[0] = 0x01;
    ok.extranonce_prefix[1] = 0x02;
    ok.extranonce_prefix[2] = 0x03;
    ok.extranonce_prefix[3] = 0x04;

    if (sv2_send_open_standard_channel_success(fd, &ok) != 0) {
        fprintf(stderr, "[mining] failed to send OpenStandardMiningChannel.Success\n");
        return -1;
    }
    fprintf(stdout, "[mining] sent OpenStandardMiningChannel.Success (chan=%u)\n", ok.channel_id);

    // 2) SetTarget (mirror max_target)
    sv2_SetTarget st;
    memset(&st, 0, sizeof(st));
    st.channel_id = ok.channel_id;
    st.maximum_target = m->max_target;

    if (sv2_send_set_target(fd, &st) != 0) {
        fprintf(stderr, "[mining] failed to send SetTarget\n");
        return -1;
    }
    fprintf(stdout, "[mining] sent SetTarget\n");

    // 3) NewMiningJob (stubbed: empty coinbase + merkle)
    sv2_NewMiningJob nj;
    memset(&nj, 0, sizeof(nj));
    nj.channel_id = ok.channel_id;
    nj.job_id     = 1;
    nj.is_future_job = 0;
    nj.version    = 0x20000000;  // segwit-enabled example
    nj.coinbase_tx_prefix      = NULL;
    nj.coinbase_tx_prefix_len  = 0;
    nj.coinbase_tx_suffix      = NULL;
    nj.coinbase_tx_suffix_len  = 0;
    nj.merkle_branch           = NULL;
    nj.merkle_count            = 0;

    if (sv2_send_new_mining_job(fd, &nj) != 0) {
        fprintf(stderr, "[mining] failed to send NewMiningJob\n");
        return -1;
    }
    fprintf(stdout, "[mining] sent NewMiningJob (job_id=%u)\n", nj.job_id);

    // 4) SetNewPrevHash (dummy)
    sv2_SetNewPrevHash snph;
    memset(&snph, 0, sizeof(snph));
    snph.channel_id = ok.channel_id;
    snph.job_id     = nj.job_id;
    zero32(snph.prev_hash);                 // all-zero prevhash (demo)
    snph.min_ntime  = now_ntime_le();
    snph.nbits      = 0x1d00ffff;           // Bitcoin mainnet-style compact (demo)

    if (sv2_send_set_new_prev_hash(fd, &snph) != 0) {
        fprintf(stderr, "[mining] failed to send SetNewPrevHash\n");
        return -1;
    }
    fprintf(stdout, "[mining] sent SetNewPrevHash\n");

    return 0;
}

static int on_submit_shares_standard(int fd, const sv2_SubmitSharesStandard *s) {
    fprintf(stdout,
            "[mining] SubmitSharesStandard: chan=%u seq=%u job=%u nonce=%u ntime=%u\n",
            s->channel_id, s->sequence_number, s->job_id, s->nonce, s->ntime);

    // trivial ack that increments counts
    static uint64_t shares_sum = 0;
    shares_sum += 1;

    sv2_SubmitSharesSuccess ok;
    memset(&ok, 0, sizeof(ok));
    ok.channel_id                 = s->channel_id;
    ok.last_sequence_number       = s->sequence_number;
    ok.new_submits_accepted_count = 1;
    ok.new_shares_sum             = shares_sum;

    if (sv2_send_submit_shares_success(fd, &ok) != 0) {
        fprintf(stderr, "[mining] failed to send SubmitShares.Success\n");
        return -1;
    }
    fprintf(stdout, "[mining] sent SubmitShares.Success (seq=%u)\n", ok.last_sequence_number);
    return 0;
}

// ---- dispatcher -----------------------------------------------------

static int dispatch_one(int fd, const sv2_frame_t *f) {
    if (f->ext != SV2_EXT_MINING) {
        fprintf(stderr, "[mining] unexpected ext=0x%04x (want 0x%04x)\n",
                f->ext, SV2_EXT_MINING);
        return -1;
    }

    switch (f->msg_type) {
    case SV2_MSG_OPEN_STANDARD_MINING_CHANNEL: {
        sv2_OpenStandardMiningChannel m;
        memset(&m, 0, sizeof(m));
        if (sv2_dec_open_standard_channel(f->payload, f->len, &m) != 1) {
            fprintf(stderr, "[mining] decode OpenStandardMiningChannel failed\n");
            return -1;
        }
        return on_open_standard_channel(fd, &m);
    }

    case SV2_MSG_SUBMIT_SHARES_STANDARD: {
        sv2_SubmitSharesStandard sub;
        memset(&sub, 0, sizeof(sub));
        if (sv2_dec_submit_shares_standard(f->payload, f->len, &sub) != 1) {
            fprintf(stderr, "[mining] decode SubmitSharesStandard failed\n");
            return -1;
        }
        return on_submit_shares_standard(fd, &sub);
    }

    default:
        fprintf(stderr, "[mining] unhandled msg_type=0x%02x\n", f->msg_type);
        return 0; // ignore unknown for now
    }
}

// ---- simple run loop (call after SetupConnection.Success) ------------

int mining_run_after_setup(int fd) {
    for (;;) {
        uint8_t ibuf[1 << 16];
        size_t ilen = 0;
        if (sv2_read_len_prefixed(fd, ibuf, sizeof(ibuf), &ilen) != 0) {
            fprintf(stderr, "[mining] read frame failed (peer closed?)\n");
            return -1;
        }
        sv2_frame_t f;
        if (sv2_parse_frame(ibuf, ilen, &f) != 1) {
            fprintf(stderr, "[mining] bad frame\n");
            return -1;
        }
        if (dispatch_one(fd, &f) != 0) {
            // on hard error, drop connection
            return -1;
        }
    }
}
