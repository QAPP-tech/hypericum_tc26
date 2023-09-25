#pragma once

#include "streebog.h"

#include <stdio.h>


void randombytes_init(
    unsigned char* entropy_input,
    unsigned char* personalization_string,
    int security_strength);

// Р 1323565.1.006-2017 standard
int randombytes(const hash_algo_t hash_algo, uint8_t* x, size_t xlen);
