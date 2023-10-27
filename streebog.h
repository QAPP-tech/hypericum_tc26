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

#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Type definition for hashing function
 *
 * @param buf Data to hash.
 * @param len Data buffer length.
 * @param[out] out Buffer which receives hash, should be not less than
 *   `hash_algo_st.output_size`.
 */
typedef void (*hash_function_t)(const uint8_t* buf, size_t len, uint8_t* out);

/**
 * @brief Opaque handle to hash function context
 */
typedef void* hash_function_ctx_t;

/**
 * @brief Type definition for hashing context creation and initialization
 * function
 *
 * When implementing this function, create your algorithm handle on the heap and
 * return it casted to hash_function_ctx_t
 *
 * @return Hashing context opaque handle.
 */
typedef hash_function_ctx_t (*hash_function_ctx_new_t)();

/**
 * @brief Type definition to init a fresh context, possibly reusing the old one
 */
typedef void (*hash_function_init_t)(hash_function_ctx_t ctx);

/**
 * @brief Type definition for hashing update function
 *
 * @param ctx Hashing context created by hash_function_ctx_new_t function
 * @param msg Data to hash
 * @param len Data buffer length
 */
typedef void (*hash_function_update_t)(
    hash_function_ctx_t ctx, const uint8_t* msg, size_t len);

/**
 * @brief Type definition for hashing finalization function
 *
 * @param ctx Hashing context created by hash_function_ctx_new_t function
 * @param[out] out Buffer which receives hash, should be not less than
 *   `hash_algo_st.output_size`.
 */
typedef void (*hash_function_final_t)(hash_function_ctx_t ctx, uint8_t* out);

/**
 * @brief Type definition for hashing context freeing function
 *
 * @param ctx Hashing context created by hash_function_ctx_new_t function
 */
typedef void (*hash_function_ctx_free_t)(hash_function_ctx_t ctx);


/**
 * @brief Structure representing SPHINCS+ hashing algorithm context
 *
 * You may specify either hash_function or the four functions ctx_new, update,
 * final, ctx_free, or all functions.
 *
 * NOTE: If you don't specify any function, you MUST set it to NULL.
 */
struct hash_algo_st
{
    hash_function_t hash;  ///< Function for hashing one buffer

    /**
     * @brief This function creates and initializes reusable hashing context to
     * hash several buffers consequently.
     */
    hash_function_ctx_new_t ctx_new;

    /**
     * @brief Function to init a fresh context, possibly reusing the old one
     */
    hash_function_init_t ctx_init;

    /**
     * @brief Function to update hash with input buffer
     */
    hash_function_update_t ctx_update;

    /**
     * @brief Function to finalize hashing and get the digest
     */
    hash_function_final_t ctx_final;

    /**
     * @brief Function to free the context created by ctx_new.
     */
    hash_function_ctx_free_t ctx_free;

    size_t block_size;   ///< Hashing function block size
    size_t output_size;  ///< Hashing function output size (digest length)
};

/**
 * @brief Type definition for opaque hashing algorithm handle
 */
typedef struct hash_algo_st* hash_algo_t;

/**
 * @return Hashing algorithm instance or `NULL` if out of memory
 */
hash_algo_t hash_algo_new();

void hash_algo_free(hash_algo_t hash_algo);

/**
 * @brief Streebog digest function for different sizes
 */
void streebog_digest_f(
    const uint8_t* buf, size_t len, uint8_t* result, unsigned int digest_size);
