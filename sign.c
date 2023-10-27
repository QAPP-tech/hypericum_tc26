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
#include "drbg.h"
#include "hash.h"
#include "fors.h"
#include "xmssmt.h"
#include "pack.h"
#include "params.h"
#include "utils.h"

#include <string.h>


int hypericum_generate_keys(uint8_t* result_sk, uint8_t* result_pk)
{
    const hash_algo_t hash_algo = hash_algo_new();

    hypericum_pk_internal_t pk = hypericum_pk_parse(result_pk);
    hypericum_sk_internal_t sk = hypericum_sk_parse(result_sk);

    int ret = 0;
    if ((ret = randombytes(hash_algo, sk.seed, HYPERICUM_N_BYTES)) != 0) {
        hash_algo_free(hash_algo);
        return ret;
    }

    if ((ret = randombytes(hash_algo, sk.prf, HYPERICUM_N_BYTES)) != 0) {
        hash_algo_free(hash_algo);
        return ret;
    }

    if ((ret = randombytes(hash_algo, pk.seed, HYPERICUM_N_BYTES)) != 0) {
        hash_algo_free(hash_algo);
        return ret;
    }

    hypericum_generate_xmssmt_pk(hash_algo, sk.seed, pk.seed, pk.root);

    memcpy(result_sk + HYPERICUM_N_BYTES * 2, result_pk, HYP_PUBLIC_KEY_BYTES);

    hash_algo_free(hash_algo);
    return ret;
}

static uint32_t be_to_u32(uint8_t* a)
{
    uint32_t ret = a[0];
    for (uint8_t i = 1; i < 4; ++i) {
        ret = (ret << 8) | a[i];
    }
    return ret;
}

static uint64_t be_to_u64(uint8_t* a)
{
    uint64_t ret = a[0];
    for (uint8_t i = 1; i < 8; ++i) {
        ret = (ret << 8) | a[i];
    }
    return ret;
}

int hypericum_sign(
    const uint8_t* sk_bytes,
    const uint8_t* msg,
    size_t msg_len,
    uint8_t* result_sig)
{
    int ret = 0;
    const hash_algo_t hash_algo = hash_algo_new();

    hypericum_sk_internal_t sk = hypericum_sk_parse((uint8_t*)sk_bytes);
    hypericum_sig_internal_t sig = hypericum_sig_parse(result_sig);

    hypericum_prf_msg(
        hash_algo, sk.prf, sk.pk.seed, (const uint8_t*)HYPERICUM_OPT, msg,
        msg_len, sig.r);

    const uint32_t tmp_md_size = (HYP_K * HYP_B + 7) / 8;
    const uint32_t tmp_idx_tree_size = (HYP_H - HYP_H_PRIME + 7) / 8;

    uint8_t digest[64];
    uint64_t idx_tree = 0;
    uint32_t idx_leaf = 0;
    uint8_t s_found = 0;

    for (uint32_t i = 0; i < HYPERICUM_SIGN_MAX_ITERATIONS; ++i) {
        if ((ret = randombytes(hash_algo, sig.s, HYPERICUM_N_BYTES)) != 0) {
            hash_algo_free(hash_algo);
            return ret;
        }

        hypericum_h_msg(
            hash_algo, sig.r, sk.pk.seed, sk.pk.root, sig.s, msg, msg_len,
            digest);

        if (md_suffix_nonzero(digest)) {
            continue;
        }
        s_found = 1;

        uint8_t* tmp_idx_tree = digest + tmp_md_size;
        idx_tree = be_to_u64(tmp_idx_tree);
        idx_tree >>= (64 - HYP_H + HYP_H_PRIME);

        uint8_t* tmp_idx_leaf = tmp_idx_tree + tmp_idx_tree_size;
        idx_leaf = be_to_u32(tmp_idx_leaf);
        idx_leaf >>= (32 - HYP_H_PRIME);
        break;
    }

    hypericum_adrs_t* adrs = hypericum_adrs_create();

    hypericum_adrs_set_layer_address(adrs, 0);
    hypericum_adrs_set_tree_address(adrs, idx_tree);
    hypericum_adrs_set_type(adrs, address_fors_tree);
    hypericum_adrs_set_keypair_address(adrs, idx_leaf);
    hypericum_sign_fors(
        hash_algo, sk.seed, sk.pk.seed, digest, adrs, sig.sig_fors);

    uint8_t pk_fors[HYPERICUM_N_BYTES];
    hypericum_generate_fors_pk_from_sig(
        hash_algo, sk.pk.seed, digest, sig.sig_fors, adrs, pk_fors);

    hypericum_adrs_set_type(adrs, address_tree);
    hypericum_adrs_destroy(adrs);
    secure_erase(digest, 64);
    hypericum_sign_xmssmt(
        hash_algo, sk.seed, sk.pk.seed, pk_fors, idx_tree, idx_leaf,
        sig.sig_ht);

    hash_algo_free(hash_algo);
    return ret;
}

int hypericum_verify(
    const uint8_t* pk_bytes,
    const uint8_t* sig_bytes,
    const uint8_t* msg,
    size_t msg_len)
{
    const hash_algo_t hash_algo = hash_algo_new();

    hypericum_pk_internal_t pk = hypericum_pk_parse((uint8_t*)pk_bytes);
    hypericum_sig_internal_t sig = hypericum_sig_parse((uint8_t*)sig_bytes);

    uint8_t digest[64];
    hypericum_h_msg(
        hash_algo, sig.r, pk.seed, pk.root, sig.s, msg, msg_len, digest);
    if (md_suffix_nonzero(digest)) {
        hash_algo_free(hash_algo);
        return 1;
    }

    const uint32_t tmp_md_size = (HYP_K * HYP_B + 7) / 8;
    const uint32_t tmp_idx_tree_size = (HYP_H - HYP_H_PRIME + 7) / 8;

    uint8_t* tmp_idx_tree = digest + tmp_md_size;
    uint64_t idx_tree = be_to_u64(tmp_idx_tree);
    idx_tree >>= (64 - HYP_H + HYP_H_PRIME);

    uint8_t* tmp_idx_leaf = tmp_idx_tree + tmp_idx_tree_size;
    uint32_t idx_leaf = be_to_u32(tmp_idx_leaf);
    idx_leaf >>= (32 - HYP_H_PRIME);

    hypericum_adrs_t* adrs = hypericum_adrs_create();
    hypericum_adrs_set_layer_address(adrs, 0);
    hypericum_adrs_set_tree_address(adrs, idx_tree);
    hypericum_adrs_set_type(adrs, address_fors_tree);
    hypericum_adrs_set_keypair_address(adrs, idx_leaf);

    uint8_t pk_fors[HYPERICUM_N_BYTES];
    hypericum_generate_fors_pk_from_sig(
        hash_algo, pk.seed, digest, sig.sig_fors, adrs, pk_fors);

    hypericum_adrs_set_type(adrs, address_tree);
    hypericum_adrs_destroy(adrs);
    int ret = 1 - hypericum_verify_xmssmt(
                      hash_algo, pk.seed, sig.sig_ht, pk_fors, idx_tree,
                      idx_leaf, pk.root);

    hash_algo_free(hash_algo);
    return ret;
}
