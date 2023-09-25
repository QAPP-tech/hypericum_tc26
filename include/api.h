#pragma once

#include "params.h"

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_SECRETKEYBYTES HYP_SECRET_KEY_BYTES
#define CRYPTO_PUBLICKEYBYTES HYP_PUBLIC_KEY_BYTES
#define CRYPTO_BYTES HYP_SIGNATURE_BYTES

#define CRYPTO_ALGNAME "Hypericum"

int crypto_sign_keypair(unsigned char* pk, unsigned char* sk);

int crypto_sign(
    unsigned char* sm,
    unsigned long long* smlen,
    const unsigned char* m,
    unsigned long long mlen,
    const unsigned char* sk);

int crypto_sign_open(
    unsigned char* m,
    unsigned long long* mlen,
    const unsigned char* sm,
    unsigned long long smlen,
    const unsigned char* pk);
