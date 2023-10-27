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
#include "api.h"
#include "streebog.h"

#include <stdint.h>

#include <stdint.h>

/**
 * @brief Generates FORS+C secret key. `FORS.SKgen` algorithm from
 * specification.
 * @param[in] `hypericum` Hypericum context.
 * @param[in] `sk_seed` Secret key seed, length is `HYPERICUM_N_BYTES`.
 * @param[in] `pk_seed` Public key seed, length is `HYPERICUM_N_BYTES`.
 * @param[in] idx Index
 * @param[in] adrs hypericum addressing structure.
 * @param[out] result `HYPERICUM_N_BYTES` hash result.
 */
void hypericum_generate_fors_sk(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    uint32_t idx,
    hypericum_adrs_t* adrs,
    uint8_t* result);

/**
 * @brief Generates FORS+C signature. `FORS.sign` algorithm from specification.
 * @param[in] `hypericum` Hypericum context.
 * @param[in] `sk_seed` Secret key seed, length is `HYPERICUM_N_BYTES`.
 * @param[in] `pk_seed` Public key seed, length is `HYPERICUM_N_BYTES`.
 * @param[in] msg Message of size `forsc_msg_bytes`.
 * @param[in] adrs hypericum addressing structure.
 * @param[out] result `HYPERICUM_N_BYTES` hash result.
 */
void hypericum_sign_fors(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    const uint8_t* msg,
    hypericum_adrs_t* adrs,
    uint8_t* result);


/**
 * @brief Calculates FORS+C public key from signature. `FORS.pkFromSig`
 * algorithm from specification.
 * @param[in] `hypericum` Hypericum context.
 * @param[in] `pk_seed` Public key seed, length is `HYPERICUM_N_BYTES`.
 * @param[in] msg Message of size `HYPERICUM_N_BYTES`.
 * @param[in] sig FORS signature of size `HYPERICUM_N_BYTES`.
 * @param[in] adrs hypericum addressing structure.
 * @param[out] result `HYPERICUM_N_BYTES` hash result.
 */
void hypericum_generate_fors_pk_from_sig(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const uint8_t* msg,
    const uint8_t* sig,
    hypericum_adrs_t* adrs,
    uint8_t* result);
