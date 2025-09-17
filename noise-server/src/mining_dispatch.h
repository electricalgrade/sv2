#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Run a minimal SV2 mining loop on an already handshaken socket.
// Returns 0 on clean EOF, <0 on error.
#pragma once
int mining_run_after_setup(int fd);

#ifdef __cplusplus
}
#endif
