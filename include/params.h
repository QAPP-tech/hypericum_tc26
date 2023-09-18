#pragma once

#include "current-paramset.h"

#include <stdint.h>

#define HYPERICUM_N_BYTES 32
#define HYPERICUM_N_BITS (HYPERICUM_N_BYTES * 8)
#define HYPERICUM_H_NONCE_BYTES 4
#define HYPERICUM_H_NONCE_BITS (HYPERICUM_H_NONCE_BYTES * 8)

#define HYPERICUM_MAX_ITERATIONS 186731
#define HYPERICUM_SIGN_MAX_ITERATIONS 23258071

#define HYPERICUM_OPT \
    "5475726368656e6b6f7c4b5544494e4f567c477265626e65767c514150500d0a"


static uint32_t log_w(uint32_t w)
{
    uint32_t result = 0;
    while (w >>= 1) {
        result++;
    }
    return result;
}


/* derived parameteres */

#define HYP_L (HYPERICUM_N_BITS / log_w(HYP_W))
#define HYP_K_HATCH (HYP_K - 1)
#define HYP_H_PRIME (HYP_H / HYP_D)
#define HYP_S_WN ((HYP_W - 1) * HYP_L >> 1)
#define HYP_WOTS_BYTES (HYP_L * HYPERICUM_N_BYTES + HYPERICUM_H_NONCE_BYTES)
#define HYP_XMSSMT_BYTES \
    (HYP_D *             \
     ((HYP_L + HYP_H_PRIME) * HYPERICUM_N_BYTES + HYPERICUM_H_NONCE_BYTES))

#define HYP_FORSC_BYTES ((HYP_B + 1) * HYP_K_HATCH * HYPERICUM_N_BYTES)
// PK.seed || PK.root
#define HYP_PUBLIC_KEY_BYTES (HYPERICUM_N_BYTES + HYPERICUM_N_BYTES)

// SK.seed + SK.prf + PK
#define HYP_SECRET_KEY_BYTES \
    (HYPERICUM_N_BYTES + HYPERICUM_N_BYTES + HYP_PUBLIC_KEY_BYTES)

// R + s + SIG_FORS + SIG_HT
#define HYP_SIGNATURE_BYTES \
    (HYPERICUM_N_BYTES + HYPERICUM_N_BYTES + HYP_FORSC_BYTES + HYP_XMSSMT_BYTES)
