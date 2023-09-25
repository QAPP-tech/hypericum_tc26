#include "drbg.h"

#include "sei.h"
#include "utils.h"

#include <string.h>

void randombytes_init(
    unsigned char* entropy_input,
    unsigned char* personalization_string,
    int security_strength)
{}

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
    const size_t init_len = 32;  // initial number of random bytes
    uint8_t* x_ptr = x + xlen;   // end of x

    hash_function_ctx_new_t ctx = hash_algo->ctx_new();

    ALLOC_ON_STACK(uint8_t, u, hash_algo->block_size - 1);

    memset(x, 0, xlen);

    if (get_entropy(u, init_len) != 0) {
        return 1;
    }
    memset(u + init_len, 0, sizeof(u) - init_len);

    if (q != 0) {  // step 4
        for (size_t i = 0; i < q; ++i) {
            x_ptr -= hash_algo->output_size;  // C_i || R
            if (0 != step(hash_algo, ctx, u, sizeof(u), x_ptr)) {
                hash_algo->ctx_free(ctx);
                return 1;
            }
        }
    }

    if (r != 0) {  // step 5
        ALLOC_ON_STACK(uint8_t, tmp, hash_algo->output_size);
        if (0 != step(hash_algo, ctx, u, sizeof(u), tmp)) {
            hash_algo->ctx_free(ctx);
            return 1;
        }
        // r least significant bytes
        memcpy(x, tmp + sizeof(tmp) - r, r);
    }

    hash_algo->ctx_free(ctx);
    return 0;
}
