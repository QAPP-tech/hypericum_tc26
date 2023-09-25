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
