#pragma once

#include <stddef.h>
#include <stdint.h>

int hypericum_generate_keys(uint8_t* pk, uint8_t* sk);

int hypericum_sign(
    const uint8_t* sk, const uint8_t* m, size_t mlen, uint8_t* sm);

int hypericum_verify(
    const uint8_t* pk, const uint8_t* sm, const uint8_t* m, size_t mlen);
