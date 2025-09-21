#pragma once
// datum_sv2.h — DATUM <-> Stratum V2 glue (uses your generic sv2_adapter)

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle - this is the same type as Sv2Server from sv2_adapter.h
typedef struct Sv2Server Sv2Handle;

/**
 * Start the SV2 listener on bind_ip:port (e.g. "0.0.0.0", 3333).
 * Returns an opaque handle (or NULL on failure).
 */
Sv2Handle* datum_sv2_start(const char *bind_ip, int port);

/** Stop the SV2 listener and free resources. */
void datum_sv2_stop(Sv2Handle *h);

/** Push a new target to a specific channel_id (as assigned by the adapter). */
int datum_sv2_set_target(uint32_t channel_id, uint32_t le_target);

/** Broadcast a new mining job to all open channels. */
int datum_sv2_broadcast_job(uint32_t job_id,
                            const uint8_t merkle_root[32],
                            uint32_t version,
                            uint32_t ntime_le,
                            uint32_t nbits_le);

/* -----------------------------------------------------------------------
   Hooks expected from DATUM core (you likely already have equivalents).
   Provide these in your codebase; defaults (weak stubs) are supplied in
   datum_sv2.c so you can compile/run immediately.
   ----------------------------------------------------------------------- */

/**
 * Validate a submitted share. Return non-zero to accept, 0 to reject.
 * ntime/version are 4 little-endian bytes as sent by the miner.
 */
int datum_validate_share(uint32_t channel_id, uint32_t job_id, uint32_t nonce,
                         const uint8_t ntime[4], const uint8_t version[4]);

/** Optional: called when a miner connects (after TCP accept). */
void datum_on_connect(uint32_t channel_id);

/** Optional: called when a miner disconnects. */
void datum_on_disconnect(uint32_t channel_id);

#ifdef __cplusplus
}
#endif
