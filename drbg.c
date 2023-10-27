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

#include "drbg.h"

#include "sei.h"
#include "utils.h"

#include <string.h>

static drbg_state DRBG_ctx = { .entropy_source = { 0 },
                               .is_hardware_based = 1 };

void randombytes_init(uint8_t* entropy_input)
{
    if (entropy_input == NULL) {
        DRBG_ctx.is_hardware_based = 1;
    } else {
        DRBG_ctx.is_hardware_based = 0;
        // set initial seed
        memcpy(DRBG_ctx.entropy_source, entropy_input, DRBG_INIT_BYTES_LEN);
    }
}

// get entropy from hardware or recursively deduce from seed
static int get_entropy(
    const hash_algo_t hash_algo, hash_function_ctx_new_t ctx, void* data)
{
    int ret = 0;
    if (1 == DRBG_ctx.is_hardware_based) {
        ret = get_hardware_entropy(data, DRBG_INIT_BYTES_LEN);
    } else {
        // recursively update state
        hash_algo->ctx_init(ctx);  // clean state
        hash_algo->ctx_update(
            ctx, DRBG_ctx.entropy_source, DRBG_INIT_BYTES_LEN);
        hash_algo->ctx_final(ctx, DRBG_ctx.entropy_source);  // compute hash

        // copy current pseudorandomness
        memcpy(data, DRBG_ctx.entropy_source, DRBG_INIT_BYTES_LEN);
    }
    return ret;
}

// increment big integer, least significant bit is the right most
// { 0x00, 0x00, 0xFF, 0x00 } -> {0x00, 0x00, 0xFF, 0x01}, return 0
// { 0x00, 0x00, 0xFF, 0xFF } -> {0x00, 0x01, 0x00, 0x00}, return 0
// { 0xFF, 0xFF, 0xFF, 0xFF } -> {0x00, 0x00, 0x00, 0x00}, return 1
static int increment(uint8_t* big_integer, size_t len)
{
    uint8_t overflow = 1;
    // loop i : len-1 , ... , 0
    for (size_t i = len - 1; i + 1 > 0 && overflow; --i) {
        uint8_t c = big_integer[i];
        big_integer[i] = c + overflow;

        overflow = c == UINT8_MAX;
    }
    return overflow;
}

static int step(
    const hash_algo_t hash_algo,
    hash_function_ctx_new_t ctx,
    uint8_t* u,
    size_t ulen,
    uint8_t* hash_output)
{
    if (0 != increment(u, ulen)) {
        return 1;
    }
    // skip mod 2^(m-8) step because in Hypericum q={0, 1} and l=248 bit
    // so u is always less then 2^(m-8)

    hash_algo->ctx_init(ctx);  // clean state
    hash_algo->ctx_update(ctx, u, ulen);
    hash_algo->ctx_final(ctx, hash_output);  // compute hash

    return 0;
}

int randombytes(const hash_algo_t hash_algo, uint8_t* x, size_t xlen)
{
    const size_t q = xlen / hash_algo->output_size;
    const size_t r = xlen % hash_algo->output_size;
    uint8_t* x_ptr = x + xlen;  // end of x

    hash_function_ctx_new_t ctx = hash_algo->ctx_new();

    ALLOC_ON_STACK(uint8_t, u, hash_algo->block_size - 1);

    memset(x, 0, xlen);

    int ret = 0;
    if ((ret = get_entropy(hash_algo, ctx, u)) != 0) {
        goto cleanup;
    }

    memset(u + DRBG_INIT_BYTES_LEN, 0, sizeof(u) - DRBG_INIT_BYTES_LEN);

    if (q != 0) {  // step 4
        for (size_t i = 0; i < q; ++i) {
            x_ptr -= hash_algo->output_size;  // C_i || R
            if ((ret = step(hash_algo, ctx, u, sizeof(u), x_ptr)) != 0) {
                goto cleanup;
            }
        }
    }

    if (r != 0) {  // step 5
        ALLOC_ON_STACK(uint8_t, tmp, hash_algo->output_size);
        if ((ret = step(hash_algo, ctx, u, sizeof(u), tmp)) != 0) {
            goto cleanup;
        }
        // r least significant bytes
        memcpy(x, tmp + sizeof(tmp) - r, r);
    }

cleanup:
    hash_algo->ctx_free(ctx);
    return ret;
}
