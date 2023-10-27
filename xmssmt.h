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

#include "streebog.h"

#include <stdint.h>


/**
 * @brief Generate hypertree public key.
 * @param hypericum Hypericum context
 * @param [in] sk_seed Secret key seed of length N
 * @param [in] pk_seed Public key seed of length N
 * @param [out] result hypertree public key of length N
 */
void hypericum_generate_xmssmt_pk(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    uint8_t* result);

/**
 * @brief Generate hypertree signature.
 * @param hypericum Hypericum context
 * @param [in] sk_seed Secret key seed of length N
 * @param [in] pk_seed Public key seed of length N
 * @param [in] msg Message of length N
 * @param [in] idx_tree hypertree index
 * @param [in] idx_leaf leaf index in a hypertree with index `idx_tree`
 * @param [out] result hypertree signature of length `HYP_XMSSMT_BYTES`
 */
void hypericum_sign_xmssmt(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    const uint8_t* msg,
    uint64_t idx_tree,
    uint32_t idx_leaf,
    uint8_t* result);


/**
 * @brief Verify hypertree signature.
 * @param hypericum Hypericum context
 * @param [in] pk_seed Public key seed of length N
 * @param [in] sig hypertree signature of length `HYP_XMSSMT_BYTES`
 * @param [in] msg Message of length N
 * @param [in] idx_tree hypertree index
 * @param [in] idx_leaf leaf index in a hypertree with index `idx_tree`
 * @param [in] pk hypertree root of length N
 * @param [returns] 1 on success, 0 otherwise
 */
int hypericum_verify_xmssmt(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const uint8_t* sig,
    const uint8_t* msg,
    uint64_t idx_tree,
    uint32_t idx_leaf,
    const uint8_t* pk);
