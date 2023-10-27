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

#include "adrs.h"
#include "streebog.h"

#include <stdint.h>

/**
 * @brief Calculates Xmss tree hash
 * @param [in] hypericum Hypericum context
 * @param [in] sk_seed Sekret key seed with length HYPERICUM_N_BYTES
 * @param [in] pk_seed Public key seed with length HYPERICUM_N_BYTES
 * @param [in] start_index Start index in xmss tree
 * @param [in] target_node_h Taget node height
 * @param [in] adrs Hypericum address
 * @param [out] result Stores xmss tree hash with size HYPERICUM_N_BYTES
 */
void hypericum_xmss_tree_hash(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    uint32_t start_index,
    uint32_t target_node_h,
    hypericum_adrs_t* adrs,
    uint8_t* result);

/**
 * @brief Calculates Xmss public key
 * @param [in] hypericum Hypericum context
 * @param [in] sk_seed Sekret key seed with length HYPERICUM_N_BYTES
 * @param [in] pk_seed Public key seed with length HYPERICUM_N_BYTES
 * @param [in] adrs Hypericum address
 * @param [out] result Stores public key with size HYPERICUM_N_BYTES
 */
void hypericum_xmss_pk(
    const hash_algo_t hash_algo,
    const void* sk_seed,
    const void* pk_seed,
    hypericum_adrs_t* adrs,
    uint8_t* result);

/**
 * @brief Calculates Xmss signature
 * @param [in] hypericum Hypericum context
 * @param [in] sk_seed Sekret key seed with length HYPERICUM_N_BYTES
 * @param [in] pk_seed Public key seed with length HYPERICUM_N_BYTES
 * @param [in] msg Message to sign with length HYPERICUM_N_BYTES
 * @param [in] idx Index of xmss tree
 * @param [in] adrs Hypericum address
 * @param [out] result Stores signature with length wots_bytes (wotsc sign
 * length) + HYPERICUM_N_BYTES*h_prime (auth length)
 */
void hypericum_xmss_sign(
    const hash_algo_t hash_algo,
    const void* sk_seed,
    const void* pk_seed,
    const uint8_t* msg,
    uint32_t idx,
    hypericum_adrs_t* adrs,
    uint8_t* result);

/**
 * @brief Calculates Xmss public key from signature
 * @param [in] hypericum Hypericum context
 * @param [in] pk_seed Public key seed with length HYPERICUM_N_BYTES
 * @param [in] msg Message with length HYPERICUM_N_BYTES
 * @param [in] sig Xmss signature of message with length wots_bytes (wotsc sign
 * length) + HYPERICUM_N_BYTES*h_prime (auth length)
 * @param [in] idx Index of xmss tree
 * @param [in] adrs Hypericum address
 * @param [out] result Stores public key calculated from signature with length
 * HYPERICUM_N_BYTES
 */
void hypericum_xmss_pk_from_sig(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const uint8_t* msg,
    const uint8_t* sig,
    uint32_t idx,
    hypericum_adrs_t* adrs,
    uint8_t* result);
