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
