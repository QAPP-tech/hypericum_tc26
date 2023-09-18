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
