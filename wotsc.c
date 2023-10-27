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

#include "wotsc.h"
#include "streebog.h"
#include "drbg.h"
#include "params.h"
#include "hash.h"
#include "adrs.h"

#include "utils.h"

#include <string.h>

int chain(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const uint8_t* x,
    size_t j,
    size_t k,
    hypericum_adrs_t* adrs,
    uint8_t* element)
{
    const size_t output_size = hash_algo->output_size;

    if (k <= 0) {
        memcpy(element, x, output_size);
        return 0;
    }

    if (j + k > HYP_W - 1) {
        return EINVAL;
    }

    int res = chain(hash_algo, pk_seed, x, j, k - 1, adrs, element);

    hypericum_adrs_set_wots_hash_hash_address(adrs, j + k - 1);

    // concatenate pk_seed | adrs | element
    const size_t adrs_size = HYPERICUM_ADRS_SIZE_BYTES;
    const size_t n = HYPERICUM_N_BYTES;
    const size_t concat_len = n + adrs_size + (res == 0 ? output_size : 0);
    ALLOC_ON_STACK(uint8_t, concat, concat_len);
    memcpy(concat, pk_seed, n);
    memcpy(concat + n, adrs, adrs_size);
    if (res == 0) {
        memcpy(concat + n + adrs_size, element, output_size);
    }

    hash_algo->hash(concat, concat_len, element);

    return 0;
}

uint8_t convert_w_unpack(
    const uint8_t* msg_packed, size_t msg_len, uint16_t w, uint8_t* out)
{
    if (msg_packed == NULL || out == NULL) {
        return 1;
    }

    uint16_t wbits;
    switch (w) {
        case 4:
            wbits = 2;
            break;
        case 16:
            wbits = 4;
            break;
        case 256:
            wbits = 8;
            break;
        default:
            return 1;
    }

    uint8_t* cur = out;

    const uint16_t mask = w - 1;
    for (size_t i = 0; i < msg_len; ++i) {
        for (uint16_t acc = wbits; acc <= 8; acc += wbits, ++cur) {
            *cur = (msg_packed[i] >> (8 - acc)) & (w - 1);
        }
    }
    return 0;
}

int hash_convert(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    hypericum_adrs_t* adrs,
    const uint8_t* msg,
    uint32_t s_wn,
    uint8_t* base_w,
    uint8_t* s)
{
    int ret = 0;

    hypericum_adrs_set_type(adrs, address_sign_msg_wots);
    hypericum_adrs_set_suffix(adrs, 0);

    size_t msg_bytes = HYPERICUM_N_BYTES;

    ALLOC_ON_STACK(uint8_t, d, HYPERICUM_N_BYTES);
    uint8_t adrs_bytes[HYPERICUM_ADRS_SIZE_BYTES];

    hash_function_ctx_t h_ctx = hash_algo->ctx_new();

    for (uint32_t i = 0; i < HYPERICUM_MAX_ITERATIONS; ++i) {
        hash_algo->ctx_init(h_ctx);

        hash_algo->ctx_update(h_ctx, pk_seed, HYPERICUM_N_BYTES);

        // adrs
        hypericum_adrs_get_bytes(adrs, adrs_bytes);
        hash_algo->ctx_update(h_ctx, adrs_bytes, HYPERICUM_ADRS_SIZE_BYTES);

        if ((ret = randombytes(hash_algo, s, HYPERICUM_H_NONCE_BYTES)) != 0) {
            hash_algo->ctx_free(h_ctx);
            return ret;
        }

        // s
        hash_algo->ctx_update(h_ctx, s, HYPERICUM_H_NONCE_BYTES);

        // m
        hash_algo->ctx_update(h_ctx, msg, msg_bytes);

        hash_algo->ctx_final(h_ctx, d);
        convert_w_unpack(d, HYPERICUM_N_BYTES, HYP_W, base_w);

        uint32_t s_cur = 0;
        for (size_t i = 0; i < HYP_L; ++i) {
            s_cur += base_w[i];
        }
        if (s_cur == s_wn) {
            break;
        }
    }
    hash_algo->ctx_free(h_ctx);

    return ret;
}

int hypericum_generate_wots_sk(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    hypericum_adrs_t* adrs,
    uint8_t* result_sk)
{
    hypericum_adrs_set_type(adrs, address_keygen_wots);

    uint8_t* sk_iterator = result_sk;
    for (int i = 0; i < HYP_L; ++i, sk_iterator += HYPERICUM_N_BYTES) {
        hypericum_adrs_set_keygen_wots_chain_address(adrs, i);
        hypericum_prf(hash_algo, sk_seed, pk_seed, adrs, sk_iterator);
    }

    return 0;
}

int hypericum_generate_wots_pk(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    hypericum_adrs_t* adrs,
    uint8_t* result_pk)
{
    size_t sk_size = HYPERICUM_N_BYTES * HYP_L;
    size_t pk_tmp_size = sk_size;
    ALLOC_ON_STACK(uint8_t, sk, sk_size);
    ALLOC_ON_STACK(uint8_t, pk_tmp, pk_tmp_size);

    int err_sk =
        hypericum_generate_wots_sk(hash_algo, sk_seed, pk_seed, adrs, sk);
    if (err_sk != 0) {
        return err_sk;
    }

    hypericum_adrs_set_type(adrs, address_wots_hash);
    uint8_t* pk_iterator = pk_tmp;
    const uint8_t* sk_iterator = sk;
    for (int i = 0; i < HYP_L; i++, pk_iterator += HYPERICUM_N_BYTES,
             sk_iterator += HYPERICUM_N_BYTES) {
        hypericum_adrs_set_wots_hash_chain_address(adrs, i);
        int chain_err = chain(
            hash_algo, pk_seed, sk_iterator, 0, HYP_W - 1, adrs, pk_iterator);
        if (chain_err != 0) {
            return chain_err;
        }
    }

    hypericum_adrs_set_type(adrs, address_wots_pk);
    hypericum_thl(hash_algo, pk_seed, adrs, pk_tmp, result_pk);
    return 0;
}

int hypericum_sign_wots(
    const hash_algo_t hash_algo,
    const uint8_t* msg,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    hypericum_adrs_t* adrs,
    uint8_t* result_sig)
{
    size_t base_w_size = HYP_L;
    ALLOC_ON_STACK(uint8_t, base_w, base_w_size);

    int ret = 0;
    // first l elements are signature itself, and the last 32-bits are salt.
    uint8_t* out_salt = &result_sig[HYP_L * HYPERICUM_N_BYTES];
    if ((ret = hash_convert(
             hash_algo, pk_seed, adrs, msg, HYP_S_WN, base_w, out_salt)) != 0) {
        return ret;
    }

    size_t sk_size = HYPERICUM_N_BYTES * HYP_L;
    ALLOC_ON_STACK(uint8_t, sk, sk_size);
    int err_sk =
        hypericum_generate_wots_sk(hash_algo, sk_seed, pk_seed, adrs, sk);
    if (err_sk != 0) {
        return err_sk;
    }

    hypericum_adrs_set_type(adrs, address_wots_hash);
    uint8_t* sig_iterator = result_sig;
    const uint8_t* sk_iterator = sk;
    const uint8_t* b_iterator = base_w;
    for (int i = 0; i < HYP_L; i++, sig_iterator += HYPERICUM_N_BYTES,
             sk_iterator += HYPERICUM_N_BYTES, ++b_iterator) {
        hypericum_adrs_set_wots_hash_chain_address(adrs, i);
        int err_chain = chain(
            hash_algo, pk_seed, sk_iterator, 0, *b_iterator, adrs,
            sig_iterator);
        if (err_chain != 0) {
            return err_chain;
        }
    }

    return ret;
}

int hypericum_generate_wots_pk_from_sig(
    const hash_algo_t hash_algo,
    const uint8_t* sig,
    const uint8_t* msg,
    const uint8_t* pk_seed,
    hypericum_adrs_t* adrs,
    uint8_t* result_pk)
{
    size_t sig_size = HYP_L * HYPERICUM_N_BYTES;
    const uint8_t* s = sig + sig_size;

    hypericum_adrs_set_type(adrs, address_sign_msg_wots);
    hypericum_adrs_set_suffix(adrs, 0);

    size_t d_size = HYPERICUM_N_BYTES;
    ALLOC_ON_STACK(uint8_t, d, d_size);
    // prepare buffer consisting of pk_seed|addr|s|m to make a hash
    size_t seed_size = HYPERICUM_N_BYTES;
    size_t buffer_size = seed_size + HYPERICUM_ADRS_SIZE_BYTES +
                         HYPERICUM_H_NONCE_BYTES + HYPERICUM_N_BYTES;
    ALLOC_ON_STACK(uint8_t, buffer, buffer_size);
    memcpy(buffer, pk_seed, seed_size);
    hypericum_adrs_set_type(adrs, address_sign_msg_wots);
    hypericum_adrs_set_suffix(adrs, 0);
    hypericum_adrs_get_bytes(adrs, buffer + seed_size);
    memcpy(
        buffer + seed_size + HYPERICUM_ADRS_SIZE_BYTES, s,
        HYPERICUM_H_NONCE_BYTES);
    memcpy(buffer + buffer_size - HYPERICUM_N_BYTES, msg, HYPERICUM_N_BYTES);
    hash_algo->hash(buffer, buffer_size, d);

    size_t base_w_size = HYP_L;
    ALLOC_ON_STACK(uint8_t, base_w, base_w_size);
    convert_w_unpack(d, d_size, HYP_W, base_w);

    uint32_t s_actual = 0;
    for (size_t i = 0; i < base_w_size; ++i) {
        s_actual += base_w[i];
    }

    if (s_actual != HYP_S_WN) {
        return -1;
    }

    hypericum_adrs_set_type(adrs, address_wots_hash);
    size_t pk_tmp_size = HYP_L * HYPERICUM_N_BYTES;
    ALLOC_ON_STACK(uint8_t, pk_tmp, pk_tmp_size);
    const uint8_t* sig_iterator = sig;
    const uint8_t* b_iterator = base_w;
    uint8_t* pk_iterator = pk_tmp;
    for (int i = 0; i < HYP_L; ++i, sig_iterator += HYPERICUM_N_BYTES,
             pk_iterator += HYPERICUM_N_BYTES, ++b_iterator) {
        hypericum_adrs_set_wots_hash_chain_address(adrs, i);
        int err_chain = chain(
            hash_algo, pk_seed, sig_iterator, *b_iterator,
            HYP_W - 1 - *b_iterator, adrs, pk_iterator);
        if (err_chain != 0) {
            return 1;
        }
    }

    hypericum_adrs_set_type(adrs, address_wots_pk);
    hypericum_thl(hash_algo, pk_seed, adrs, pk_tmp, result_pk);
    return 0;
}
