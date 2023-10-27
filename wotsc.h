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
#include "string.h"

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Generates WOTS secret key
 * @param hypericum_t hypericum context,
 * @param [in] sk_seed secret key seed of length HYPERICUM_N_BYTES
 * @param [in] pk_seed public key seed of length HYPERICUM_N_BYTES
 * @param [in] adrs address structure
 * @param [out] result_sk result secret key of length HYPERICUM_N_BYTES * l
 * @return 0 in success
 */
int hypericum_generate_wots_sk(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    hypericum_adrs_t* adrs,
    uint8_t* result_sk);

/**
 * @brief Generates WOTS public key
 * @param hypericum_t hypericum context,
 * @param [in] sk_seed secret key seed of length n
 * @param [in] pk_seed public key seed of length n
 * @param [in] adrs address structure
 * @param [out] result_pk result public key
 * @return 0 in success
 */
int hypericum_generate_wots_pk(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    hypericum_adrs_t* adrs,
    uint8_t* result_pk);

/**
 * @brief Get message signature
 * @param[in] hypericum hypericum context
 * @param[in] msg message to sign
 * @param[in] sk_seed secret key seed
 * @param[in] pk_seed private key seed
 * @param[out] result_sig result signature
 * @return 0 if success
 */
int hypericum_sign_wots(
    const hash_algo_t hash_algo,
    const uint8_t* msg,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    hypericum_adrs_t* adrs,
    uint8_t* result_sig);

/**
 * @brief Get public key from signature and message
 * @param[in] sig signature
 * @param[in] msg original message of length n
 * @param[in] pk_seed public key seed of length n
 * @param[in] result_pk result public key
 */
int hypericum_generate_wots_pk_from_sig(
    const hash_algo_t hash_algo,
    const uint8_t* sig,
    const uint8_t* msg,
    const uint8_t* pk_seed,
    hypericum_adrs_t* adrs,
    uint8_t* result_pk);


/**
 * @brief Builds a chain.
 * @param hypericum Hypericum context
 * @param pk_seed public key seed, length is set by constant
 * HYPERICUM_N_BYTES
 * @param [in] x Input string of length equal to Streebog hash digest
 * @param [in] j Initial chain index
 * @param [in] k Chain length
 * @param [in] adrs Hypericum address
 * @param [out] element Result of building a chain of length equal to Streebog
 * hash digest
 * @return 0 on success
 */
int chain(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const uint8_t* x,
    size_t j,
    size_t k,
    hypericum_adrs_t* adrs,
    uint8_t* element);

/**
 * @brief packs array elements with maximum value `w` into provided buffer.
 *
 * @param[in] msg Input array
 * @param[in] msg_len Size of msg in bytes
 * @param[in] w Maximum value of input array element. Can be 4, 16 or 256.
 * @param[out] out Array of packed elements. Its size should be at least
 * `msg_len * log2(w) / 8`
 * @return 0 on success, 1 on error
 */
uint8_t convert_w_pack(
    const uint8_t* msg, size_t msg_len, uint16_t w, uint8_t* out);

/**
 * @brief unpacks array of `log2(w)`-bit elements into provided buffer.
 *
 * @param[in] msg_packed Input array
 * @param[in] msg_len Size of msg_packed in bytes
 * @param[in] w Maximum value of input array element. Can be 4, 16 or 256.
 * @param[out] out Array of unpacked elements. Its size should be at least
 * `msg_len * 8 / log2(w)`
 * @return 0 on success, 1 on error
 */
uint8_t convert_w_unpack(
    const uint8_t* msg_packed, size_t msg_len, uint16_t w, uint8_t* out);

/**
 * @brief Calculates base-`w` representation of given message `msg` such that
 * its sum equals to `s_wn`.
 *
 * @param[in] hypericum Hypericum instance
 * @param[in] pk_seed Public key seed (32 bytes)
 * @param[in] adrs Hypericum ADRS address
 * @param[in] msg Input message. Its size is `n` bytes.
 * @param[in] msg_len Input message length
 * @param[in] s_wn Target complexity
 * @param[out] base_w Unpacked streebog hash of (pk_seed, adrs, s, msg). `l`
 * bytes
 * @param[out] s Salt (`HYPERICUM_H_NONCE_BYTES`)
 * @return 0 if success
 */
int hash_convert(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    hypericum_adrs_t* adrs,
    const uint8_t* msg,
    uint32_t s_wn,
    uint8_t* base_w,
    uint8_t* s);
