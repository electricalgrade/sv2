// datum_sv2.c — DATUM <-> Stratum V2 glue (wraps sv2_adapter callbacks)

#include "datum_sv2.h"
#include "sv2/sv2_adapter.h"   // your generic adapter API
#include <string.h>

// ------------------------------------------------------------------
// Weak-default hooks so you can link & run immediately.
// Replace/override these in your DATUM core as needed.
// (GCC/Clang: weak symbol attribute)
#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
int datum_validate_share(uint32_t channel_id, uint32_t job_id, uint32_t nonce,
                         const uint8_t ntime[4], const uint8_t version[4])
{
    (void)channel_id; (void)job_id; (void)nonce; (void)ntime; (void)version;
    // Default: accept everything (demo). Implement real checks in DATUM.
    return 1;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void datum_on_connect(uint32_t channel_id){ (void)channel_id; }

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void datum_on_disconnect(uint32_t channel_id){ (void)channel_id; }
// ------------------------------------------------------------------

// Singleton-ish for now; you can refactor to multiple instances if needed.
static Sv2Server *g_sv2 = NULL;

// sv2_adapter → DATUM wrappers
static void on_connect_cb(int fd, void *user){
    (void)user;
    // In the demo adapter, channel_id == fd. If you change that mapping,
    // pass the actual channel_id from your adapter instead.
    datum_on_connect((uint32_t)fd);
}

static void on_disconnect_cb(int fd, void *user){
    (void)user;
    datum_on_disconnect((uint32_t)fd);
}

static void on_share_cb(uint32_t channel_id, uint32_t job_id, uint32_t nonce,
                        const uint8_t ntime[4], const uint8_t version[4], void *user)
{
    (void)user;
    int ok = datum_validate_share(channel_id, job_id, nonce, ntime, version);
    if (ok) sv2_ack_share(g_sv2, channel_id, /*new_shares*/1);
    else    sv2_nack_share(g_sv2, channel_id, /*err_code*/1, "low difficulty");
}

// Public API
Sv2Handle* datum_sv2_start(const char *bind_ip, int port){
    Sv2Callbacks cb = {
        .on_share      = on_share_cb,
        .on_connect    = on_connect_cb,
        .on_disconnect = on_disconnect_cb
    };
    g_sv2 = sv2_server_start(bind_ip, port, &cb, /*user*/NULL);
    return g_sv2;
}

void datum_sv2_stop(Sv2Handle *h){
    if(!h) return;
    sv2_server_stop(h);
    if(g_sv2 == h) g_sv2 = NULL;
}

int datum_sv2_set_target(uint32_t channel_id, uint32_t le_target){
    if(!g_sv2) return 0;
    return sv2_push_set_target(g_sv2, channel_id, le_target);
}

int datum_sv2_broadcast_job(uint32_t job_id,
                            const uint8_t merkle_root[32],
                            uint32_t version,
                            uint32_t ntime_le,
                            uint32_t nbits_le)
{
    if(!g_sv2) return 0;
    return sv2_broadcast_job(g_sv2, job_id, merkle_root, version, ntime_le, nbits_le);
}
