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

#include <stddef.h>
#include <stdint.h>

typedef struct hash_algo_st* hash_algo_t;
typedef struct _adrs hypericum_adrs_t;

/**
 * @brief Computes 256-bit hash with Streebog hash function.
 * Is used to compute WOTS+C chains.
 * @param hypericum Hypericum context.
 * @param pk_seed public key seed, length is set by constant
 * HYPERICUM_N_BYTES.
 * @param adrs hypericum addressing structure.
 * @param m part of hashable value of size N.
 * @param [out] result 256-bit hash result.
 */
void hypericum_f(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const hypericum_adrs_t* adrs,
    const uint8_t* m,
    uint8_t* result);

/**
 * @brief Computes 256-bit hash with Streebog hash function.
 * Is used to compute nodes in Merkle trees, including FORS.
 * @param hypericum Hypericum context.
 * @param pk_seed public key seed, length is set by constant
 * HYPERICUM_N_BYTES.
 * @param adrs hypericum addressing structure.
 * @param salt salt part for hashable value of size N.
 * @param m part of hashable value of size N.
 * @param [out] result 256-bit hash result.
 */
void hypericum_h_node(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const hypericum_adrs_t* adrs,
    const uint8_t* salt,
    const uint8_t* m,
    uint8_t* result);

/**
 * @brief Computes 256-bit hash with Streebog hash function.
 * Is used to compress WOTS+C public key.
 * @param hypericum Hypericum context.
 * @param pk_seed public key seed, length is set by constant
 * HYPERICUM_N_BYTES.
 * @param adrs hypericum addressing structure.
 * @param m part of hashable value of size N.
 * @param [out] result 256-bit hash result.
 */
void hypericum_thl(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const hypericum_adrs_t* adrs,
    const uint8_t* m,
    uint8_t* result);

/**
 * @brief Computes 256-bit hash with Streebog hash function.
 * Is used to compress FORS tree's root.
 * @param hypericum Hypericum context.
 * @param pk_seed public key seed, length is set by constant
 * HYPERICUM_N_BYTES.
 * @param adrs hypericum addressing structure.
 * @param m part of hashable value of size N.
 * @param [out] result 256-bit hash result.
 */
void hypericum_thk(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const hypericum_adrs_t* adrs,
    const uint8_t* m,
    uint8_t* result);


/**
 * @brief Hash a user input message.
 * @param hypericum Hypericum context.
 * @param rnd pseudo-random string, output of `prf_msg()`, 32 bytes
 * @param pk_seed public key seed, length is set by constant
 * HYPERICUM_N_BYTES.
 * @param pk_root public Merkle tree root hash, length is set by
 * constant HYPERICUM_N_BYTES.
 * @param salt Salt part of hashable value, size `HYPERICUM_N_BYTES`
 * @param msg input message.
 * @param msg_len message length.
 * @param [out] result 512-bit hash result.
 */
void hypericum_h_msg(
    const hash_algo_t hash_algo,
    const uint8_t* rnd,
    const uint8_t* pk_seed,
    const uint8_t* pk_root,
    const uint8_t* salt,
    const uint8_t* msg,
    size_t msg_len,
    uint8_t* result);

/**
 * @brief Pseudo-randomly generate secret key elements from a secret seed.
 * @param hypericum Hypericum context.
 * @param pk_seed public key seed, length is set by constant
 * HYPERICUM_N_BYTES.
 * @param sk_seed secret key seed, length is set by constant
 * HYPERICUM_N_BYTES.
 * @param adrs hypericum addressing structure.
 * @param [out] result 256-bit hash result.
 */
void hypericum_prf(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const uint8_t* sk_seed,
    const hypericum_adrs_t* adrs,
    uint8_t* result);

/**
 * @brief Generate a pseudo-random value used during original message
 * compression.
 * @param hypericum Hypericum context.
 * @param sk_prf a separate prf secret key seed, length is set by constant
 * HYPERICUM_N_BYTES.
 * @param pk_seed public key seed, length is set by constant
 * HYPERICUM_N_BYTES.
 * @param nonce nonce to use with hash, length is set by constant
 * HYPERICUM_N_BYTES.
 * @param msg input message.
 * @param msg_len message length.
 * @param [out] result 256-bit hash result.
 */
void hypericum_prf_msg(
    const hash_algo_t hash_algo,
    const uint8_t* sk_prf,
    const uint8_t* pk_seed,
    const uint8_t* nonce,
    const uint8_t* msg,
    size_t msg_len,
    uint8_t* result);
