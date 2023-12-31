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

#include "streebog.h"
#include "utils.h"

#include "gost3411-2012-core.h"

// return 16byte aligned context address
hash_function_ctx_t gost_create(unsigned int digest_size)
{
    GOST34112012Context* ctx;

#ifdef WIN32
    ctx = (GOST34112012Context*)_aligned_malloc(
        sizeof(GOST34112012Context), (size_t)16);
    if (ctx == NULL) {
#else   // WIN32
    if (posix_memalign((void**)&ctx, (size_t)16, sizeof(GOST34112012Context))) {
#endif  // WIN32
    }

    GOST34112012Init(ctx, digest_size);

    return (hash_function_ctx_t)ctx;
}

void gost_free(hash_function_ctx_t ctx)
{
    GOST34112012Cleanup((GOST34112012Context*)ctx);
#ifdef WIN32
    _aligned_free(ctx);
#else   // WIN32
    free(ctx);
#endif  // WIN32
}


void streebog_digest_f(
    const uint8_t* buf, size_t len, uint8_t* result, unsigned int digest_size)
{
    GOST34112012Context* ctx = gost_create(digest_size);

    GOST34112012Update(ctx, buf, len);

    GOST34112012Final(ctx, result);
    GOST34112012Cleanup(ctx);

    gost_free(ctx);
}

void gost256(const uint8_t* buf, size_t len, uint8_t* result)
{
    streebog_digest_f(buf, len, result, 256);
}

hash_function_ctx_t gost256_create()
{
    return gost_create(256);
}

void gost256_init(hash_function_ctx_t ctx)
{
    GOST34112012Init(ctx, 256);
}

void gost_update(hash_function_ctx_t ctx, const uint8_t* msg, size_t len)
{
    GOST34112012Update((GOST34112012Context*)ctx, msg, len);
}

void gost_final(hash_function_ctx_t ctx, uint8_t* out)
{
    GOST34112012Final((GOST34112012Context*)ctx, out);
}

hash_algo_t hash_algo_new()
{
    hash_algo_t hash_ctx = (hash_algo_t)calloc(1, sizeof(struct hash_algo_st));
    if (NULL == hash_ctx) {
        return NULL;
    }

    hash_ctx->hash = gost256;
    hash_ctx->block_size = 64;
    hash_ctx->output_size = 32;
    hash_ctx->ctx_new = gost256_create;
    hash_ctx->ctx_init = gost256_init;
    hash_ctx->ctx_update = gost_update;
    hash_ctx->ctx_final = gost_final;
    hash_ctx->ctx_free = gost_free;

    return hash_ctx;
}

void hash_algo_free(hash_algo_t hash_algo)
{
    free(hash_algo);
}
