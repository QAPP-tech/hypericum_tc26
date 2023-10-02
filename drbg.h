#pragma once

#include "streebog.h"

#include <stdio.h>

#define DRBG_INIT_BYTES_LEN 32

typedef struct drbg_state
{
    // entropy for pseudorandomness that is used if is_hardware_based==0
    uint8_t entropy_source[DRBG_INIT_BYTES_LEN];
    uint8_t is_hardware_based;
} drbg_state;

// Initialize drbg state, if entropy_input is NULL use hardware randomness, else
// deduce it from initial seed
void randombytes_init(uint8_t* entropy_input);

// Р 1323565.1.006-2017 standard
int randombytes(const hash_algo_t hash_algo, uint8_t* x, size_t xlen);
