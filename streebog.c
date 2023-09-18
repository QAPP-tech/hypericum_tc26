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
