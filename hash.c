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

#include "api.h"

#include "adrs.h"
#include "hash.h"
#include "streebog.h"
#include "utils.h"
#include "params.h"

#include <string.h>


static inline void _th(
    const hash_algo_t hash_algo,
    const uint8_t *pk_seed,
    const hypericum_adrs_t *adrs,
    const uint8_t *msg1,
    size_t msg1_bits,
    const uint8_t *msg2,
    size_t msg2_bits,
    uint8_t *result)
{
    size_t msg1_bytes = msg1_bits >> 3; // division by 8
    size_t msg2_bytes = msg2_bits >> 3;

    // TODO: pass ctx as a parameter to avoid memory allocation
    hash_function_ctx_new_t ctx = hash_algo->ctx_new();

    uint8_t adrs_bytes[HYPERICUM_ADRS_SIZE_BYTES];
    hypericum_adrs_get_bytes(adrs, adrs_bytes);

    const uint8_t zeros[32] = {0};

    hash_algo->ctx_update(ctx, pk_seed, HYPERICUM_N_BYTES);
    hash_algo->ctx_update(ctx, zeros, sizeof(zeros));
    hash_algo->ctx_update(ctx, adrs_bytes, HYPERICUM_ADRS_SIZE_BYTES);
    hash_algo->ctx_update(ctx, msg1, msg1_bytes);
    if (msg2 != NULL) { // providing NULL as src to memcpy is UB
        hash_algo->ctx_update(ctx, msg2, msg2_bytes);
    }

    hash_algo->ctx_final(ctx, result);
    hash_algo->ctx_free(ctx);
}

void hypericum_f(
    const hash_algo_t hash_algo,
    const uint8_t *pk_seed,
    const hypericum_adrs_t *adrs,
    const uint8_t *m,
    uint8_t *result)
{
    enum address_type adrs_type = hypericum_adrs_get_type(adrs);

    _th(hash_algo, pk_seed, adrs, m, HYPERICUM_N_BITS, NULL, 0, result);
}

// H_s(M || salt || adrs || [0, ..., 0] || pk_seed) 
// or 
// H(M2 || M1 || adrs || [0, ..., 0] || pk_seed)
void hypericum_h_node(
    const hash_algo_t hash_algo,
    const uint8_t *pk_seed,
    const hypericum_adrs_t *adrs,
    const uint8_t *salt,
    const uint8_t *m,
    uint8_t *result)
{
    enum address_type adrs_type = hypericum_adrs_get_type(adrs);

    _th(hash_algo, pk_seed, adrs, salt, HYPERICUM_N_BITS, m, HYPERICUM_N_BITS,
        result);
}

void hypericum_thl(
    const hash_algo_t hash_algo,
    const uint8_t *pk_seed,
    const hypericum_adrs_t *adrs,
    const uint8_t *m,
    uint8_t *result)
{
    enum address_type adrs_type = hypericum_adrs_get_type(adrs);

    _th(hash_algo, pk_seed, adrs, m, HYP_L * HYPERICUM_N_BITS, NULL, 0, result);
}

void hypericum_thk(
    const hash_algo_t hash_algo,
    const uint8_t *pk_seed,
    const hypericum_adrs_t *adrs,
    const uint8_t *m,
    uint8_t *result)
{
    enum address_type adrs_type = hypericum_adrs_get_type(adrs);

    _th(hash_algo, pk_seed, adrs, m, HYP_K_HATCH * HYPERICUM_N_BITS, NULL, 0,
        result);
}

// Str512(msg || salt || pk_root || pk_seed || [0, ..., 0] || rnd)
void hypericum_h_msg(
    const hash_algo_t hash_algo_512,
    const uint8_t *rnd,
    const uint8_t *pk_seed,
    const uint8_t *pk_root,
    const uint8_t *salt,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t *result)
{
    // TODO: pass ctx as a parameter to avoid memory allocation
    hash_function_ctx_new_t ctx = hash_algo_512->ctx_new();

    const size_t n = HYPERICUM_N_BYTES;
    const uint8_t zeros[32] = {0};

    hash_algo_512->ctx_update(ctx, rnd, n);
    hash_algo_512->ctx_update(ctx, zeros, sizeof(zeros));
    hash_algo_512->ctx_update(ctx, pk_seed, n);
    hash_algo_512->ctx_update(ctx, pk_root, n);
    hash_algo_512->ctx_update(ctx, salt, sizeof(uint32_t));
    hash_algo_512->ctx_update(ctx, msg, msg_len);

    hash_algo_512->ctx_final(ctx, result);
    hash_algo_512->ctx_free(ctx);
}

// Str256(adrs || pk_seed || [0, ..., 0] || sk_seed)
void hypericum_prf(
    const hash_algo_t hash_algo,
    const uint8_t *sk_seed,
    const uint8_t *pk_seed,
    const hypericum_adrs_t *adrs,
    uint8_t *result)
{
    // TODO: pass ctx as a parameter to avoid memory allocation
    hash_function_ctx_new_t ctx = hash_algo->ctx_new();

    const size_t n = HYPERICUM_N_BYTES;
    const uint8_t zeros[32] = {0};
    uint8_t adrs_bytes[HYPERICUM_ADRS_SIZE_BYTES] = {0};
    hypericum_adrs_get_bytes(adrs, adrs_bytes);

    hash_algo->ctx_update(ctx, sk_seed, n);
    hash_algo->ctx_update(ctx, zeros, sizeof(zeros));
    hash_algo->ctx_update(ctx, pk_seed, n);
    hash_algo->ctx_update(ctx, adrs_bytes, HYPERICUM_ADRS_SIZE_BYTES);

    hash_algo->ctx_final(ctx, result);
    hash_algo->ctx_free(ctx);
}

// Str256(msg || nonce || pk_seed || [0, ..., 0] || sk_prf)
void hypericum_prf_msg(
    const hash_algo_t hash_algo,
    const uint8_t *sk_prf,
    const uint8_t *pk_seed,
    const uint8_t *nonce,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t *result)
{
    // TODO: pass ctx as a parameter to avoid memory allocation
    hash_function_ctx_new_t ctx = hash_algo->ctx_new();

    const size_t n = HYPERICUM_N_BYTES;
    const uint8_t zeros[32] = {0};

    hash_algo->ctx_update(ctx, sk_prf, n);
    hash_algo->ctx_update(ctx, zeros, sizeof(zeros));
    hash_algo->ctx_update(ctx, pk_seed, n);
    hash_algo->ctx_update(ctx, nonce, n);
    hash_algo->ctx_update(ctx, msg, msg_len);

    hash_algo->ctx_final(ctx, result);
    hash_algo->ctx_free(ctx);
}

void hypericum_h_select(
    const hash_algo_t hash_algo,
    const uint8_t *pk_seed,
    const hypericum_adrs_t *adrs,
    const uint8_t *salt,
    const uint8_t *m,
    uint8_t *result)
{
    _th(hash_algo, pk_seed, adrs, salt,
        HYPERICUM_H_NONCE_BITS, m, HYPERICUM_N_BITS, result);
}

