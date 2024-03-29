/*
   This product is distributed under 2-term BSD-license terms

   Copyright (c) 2023, QApp. All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met: 

   1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma once

#include "current-paramset.h"

#include <stdint.h>

#define HYPERICUM_N_BYTES 32
#define HYPERICUM_N_BITS (HYPERICUM_N_BYTES * 8)
#define HYPERICUM_H_NONCE_BYTES 4
#define HYPERICUM_H_NONCE_BITS (HYPERICUM_H_NONCE_BYTES * 8)
// Winternitz parameter
#define HYPERICUM_W 16
#define HYPERICUM_W_BITS 4

#define HYPERICUM_MAX_ITERATIONS 186731
#define HYPERICUM_SIGN_MAX_ITERATIONS 23258071

#define HYPERICUM_OPT \
    "5475726368656e6b6f7c4b5544494e4f567c477265626e65767c514150500d0a"

/* derived parameters */

#define HYP_L (HYPERICUM_N_BITS / HYPERICUM_W_BITS)
#define HYP_K_HATCH (HYP_K - 1)
#define HYP_H_PRIME (HYP_H / HYP_D)
#define HYP_S_WN ((HYPERICUM_W - 1) * HYP_L >> 1)
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
    (HYPERICUM_N_BYTES + 4 + HYP_FORSC_BYTES + HYP_XMSSMT_BYTES)
