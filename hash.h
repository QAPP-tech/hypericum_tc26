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
