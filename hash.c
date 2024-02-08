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

// K = sk || [0,..,0]; streebog(K XOR 0x5c || streebog(K XOR 0x36 || msg))
void hmac_gostr3411_2012_256(
    const hash_algo_t streebog,
    const uint8_t *sk,
    size_t sk_len,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t *result)
{
    // TODO: pass ctx as a parameter to avoid memory allocation
    hash_function_ctx_new_t ctx = streebog->ctx_new();

    const size_t k_len = 64;
    ALLOC_ON_STACK(uint8_t, K, k_len);

    for (size_t i = 0; i < sk_len; i++)
    {
        K[i] = sk[i] ^ 0x36;
    }
    memset(K + sk_len, 0x36, k_len - sk_len);

    streebog->ctx_update(ctx, K, k_len);
    streebog->ctx_update(ctx, msg, msg_len);

    streebog->ctx_final(ctx, result);

    // start a new hashing round
    streebog->ctx_init(ctx);

    for (size_t i = 0; i < sk_len; i++)
    {
        K[i] = sk[i] ^ 0x5c;
    }
    memset(K + sk_len, 0x5c, k_len - sk_len);

    streebog->ctx_update(ctx, K, k_len);
    streebog->ctx_update(ctx, result, streebog->output_size);

    streebog->ctx_final(ctx, result);

    streebog->ctx_free(ctx);
}

// A0 = label||seed, Ai = HMAC(sk, A{i-1})
// PRF_TLS = HMAC(sk,  A1 || A0) || HMAC(sk, A2 || A0) || ...
void prf_tls_gostr3411_2012_256(
    const hash_algo_t streebog,
    const uint8_t *sk,
    size_t sk_len,
    const uint8_t *label,
    size_t label_len,
    const uint8_t *seed,
    size_t seed_len,
    size_t n_blocks,
    uint8_t *result)
{
    const size_t tmp_len = streebog->output_size + label_len + seed_len;
    // label and seed are usually small to fit on stack
    ALLOC_ON_STACK(uint8_t, tmp, tmp_len);
    memcpy(tmp + streebog->output_size, label, label_len);
    memcpy(tmp + streebog->output_size + label_len, seed, seed_len);

    uint8_t *a_i = tmp + streebog->output_size;
    size_t a_i_len = label_len + seed_len;

    for (size_t i = 0; i < n_blocks; ++i)
    {
        hmac_gostr3411_2012_256(streebog, sk, sk_len, a_i, a_i_len, tmp);

        a_i = tmp;
        a_i_len = streebog->output_size;

        hmac_gostr3411_2012_256(
            streebog, sk, sk_len, tmp, tmp_len,
            result + i * streebog->output_size);
    }
}

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
    hash_algo->ctx_update(ctx, msg2, msg2_bytes);

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

// PRF_TLS(rnd, streebog(rnd||pk_seed||pk_root||msg), pk_seed)
void hypericum_h_msg(
    const hash_algo_t hash_algo,
    const uint8_t *rnd,
    const uint8_t *pk_seed,
    const uint8_t *pk_root,
    const uint8_t *salt,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t *result)
{
    // TODO: pass ctx as a parameter to avoid memory allocation
    hash_function_ctx_new_t ctx = hash_algo->ctx_new();

    ALLOC_ON_STACK(uint8_t, tmp, hash_algo->output_size);

    const size_t n = HYPERICUM_N_BYTES;

    hash_algo->ctx_update(ctx, rnd, n);
    hash_algo->ctx_update(ctx, pk_seed, n);
    hash_algo->ctx_update(ctx, pk_root, n);
    hash_algo->ctx_update(ctx, salt, sizeof(uint32_t));
    hash_algo->ctx_update(ctx, msg, msg_len);

    hash_algo->ctx_final(ctx, tmp);
    hash_algo->ctx_free(ctx);

    prf_tls_gostr3411_2012_256(
        hash_algo, rnd, n, tmp, hash_algo->output_size, pk_seed, n, 2, result);
}

// PRF_TLS(sk_seed, adrs, pk_seed)
void hypericum_prf(
    const hash_algo_t hash_algo,
    const uint8_t *sk_seed,
    const uint8_t *pk_seed,
    const hypericum_adrs_t *adrs,
    uint8_t *result)
{
    uint8_t adrs_bytes[HYPERICUM_ADRS_SIZE_BYTES] = {0};
    hypericum_adrs_get_bytes(adrs, adrs_bytes);

    const size_t n = HYPERICUM_N_BYTES;
    prf_tls_gostr3411_2012_256(
        hash_algo, sk_seed, n, adrs_bytes, HYPERICUM_ADRS_SIZE_BYTES, pk_seed,
        n, 1, result);
}

// HMAC(sk_prf, pk_seed || nonce || msg)
void hypericum_prf_msg(
    const hash_algo_t hash_algo,
    const uint8_t *sk_prf,
    const uint8_t *pk_seed,
    const uint8_t *nonce,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t *result)
{
    const size_t n = HYPERICUM_N_BYTES;
    const size_t tmp_len = 2 * n + msg_len;
    uint8_t *tmp = malloc(tmp_len);

    memcpy(tmp, pk_seed, n);
    memcpy(tmp + n, nonce, n);
    memcpy(tmp + 2 * n, msg, msg_len);

    hmac_gostr3411_2012_256(hash_algo, sk_prf, n, tmp, tmp_len, result);

    free(tmp);
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

