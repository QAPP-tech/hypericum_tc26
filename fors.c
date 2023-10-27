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

#include "fors.h"

#include "hash.h"
#include "params.h"
#include "stack.h"
#include "utils.h"

#include <string.h>

// 'sk_seed' len: n
// 'result' len: n
void hypericum_generate_fors_sk(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    uint32_t idx,
    hypericum_adrs_t* adrs,
    uint8_t* result)
{
    hypericum_adrs_set_type(adrs, address_fors_tree);
    hypericum_adrs_set_fors_tree_height(adrs, 0);
    hypericum_adrs_set_fors_tree_index(adrs, idx);
    hypericum_prf(hash_algo, pk_seed, sk_seed, adrs, result);
}

// 'sk_seed' len: n
// 'pk_seed' len: n
// 'result' len: n
void hypericum_fors_tree_hash(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    uint32_t start_index,
    uint32_t target_node_h,
    hypericum_adrs_t* adrs,
    uint8_t* result)
{
    stack_root_t* stack_root_node = NULL;

    uint8_t sk[HYPERICUM_N_BYTES];

    for (uint32_t i = 0; i < (1u << target_node_h); i++) {
        hypericum_generate_fors_sk(
            hash_algo, sk_seed, pk_seed, start_index + i, adrs, sk);

        uint32_t node_h = 0;
        struct Node* node = hypericum_create_node(node_h);

        hypericum_f(hash_algo, pk_seed, adrs, sk, node->pk);

        hypericum_adrs_set_fors_tree_height(adrs, node_h + 1);
        hypericum_adrs_set_fors_tree_index(adrs, start_index + i);

        while (!stack_is_empty(stack_root_node) &&
               ((struct Node*)stack_peek(stack_root_node))->h == node_h) {
            hypericum_adrs_set_fors_tree_index(
                adrs, (hypericum_adrs_get_fors_tree_index(adrs) - 1) / 2);

            struct Node* top_stack_node =
                (struct Node*)stack_pop(&stack_root_node);

            hypericum_h_node(
                hash_algo, pk_seed, adrs, top_stack_node->pk, node->pk,
                node->pk);

            secure_erase(top_stack_node->pk, HYPERICUM_N_BYTES);
            free(top_stack_node);

            node_h = hypericum_adrs_get_fors_tree_height(adrs);
            hypericum_adrs_set_fors_tree_height(adrs, node_h + 1);
        }
        node->h = node_h;
        stack_push(&stack_root_node, node);
    }

    // secure sensitive data
    SECURE_ERASE(uint8_t, sk, HYPERICUM_N_BYTES);

    struct Node* top_node = (struct Node*)stack_peek(stack_root_node);
    memcpy(result, top_node->pk, HYPERICUM_N_BYTES);

    // clear stack and free all the data if needed
    while (!stack_is_empty(stack_root_node)) {
        struct Node* node = (struct Node*)stack_pop(&stack_root_node);
        secure_erase(node->pk, HYPERICUM_N_BYTES);
        free(node);
    }
}

/**
 * Interprets m as FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least FORS_HEIGHT * FORS_TREES bits.
 * Assumes indices have space for FORS_TREES integers.
 * PK: This code is copied from the reference code as there are
 * some objections about its implementation
 */
static void message_to_indices(uint32_t* indices, const unsigned char* m)
{
    uint32_t i, j;
    uint32_t offset = 0;

    for (i = 0; i < HYP_K_HATCH; i++) {
        indices[i] = 0;
        for (j = 0; j < HYP_B; j++) {
            indices[i] <<= 1;
            indices[i] ^= (m[offset >> 3] >> (offset & 0x7)) & 0x1;
            offset++;
        }
    }
}


// 'sk_seed' len: n
// 'pk_seed' len: n
// 'msg' len: fors_msg_bytes
// 'result' len: fors_bytes
void hypericum_sign_fors(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    const uint8_t* msg,
    hypericum_adrs_t* adrs,
    uint8_t* result)
{
    uint32_t t = (1u << HYP_B);

    ALLOC_ON_STACK(uint32_t, indices, HYP_K_HATCH);

    message_to_indices(indices, msg);

    for (uint32_t i = 0; i < HYP_K_HATCH; i++) {
        uint32_t idx = indices[i];

        hypericum_generate_fors_sk(
            hash_algo, sk_seed, pk_seed, i * t + idx, adrs, result);
        result += HYPERICUM_N_BYTES;

        for (uint32_t j = 0; j < HYP_B; j++) {
            uint32_t s = (idx / (1u << j)) ^ 1;
            hypericum_fors_tree_hash(
                hash_algo, sk_seed, pk_seed, i * t + s * (1u << j), j, adrs,
                result);
            result += HYPERICUM_N_BYTES;
        }
    }
    SECURE_ERASE(uint32_t, indices, HYP_K_HATCH);
}


// 'pk_seed' len: n
// 'msg' len: fors_msg_bytes
// 'sig' len: fors_bytes
// 'result' len: fors_pk_bytes (== n)
void hypericum_generate_fors_pk_from_sig(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const uint8_t* msg,
    const uint8_t* sig,
    hypericum_adrs_t* adrs,
    uint8_t* result)
{
    uint32_t t = (1u << HYP_B);

    ALLOC_ON_STACK(uint32_t, indices, HYP_K_HATCH);
    ALLOC_ON_STACK(uint8_t, roots, HYP_K_HATCH * HYPERICUM_N_BYTES);

    message_to_indices(indices, msg);
    uint8_t* roots_ptr = roots;

    hypericum_adrs_set_type(adrs, address_fors_tree);
    for (uint32_t i = 0; i < HYP_K_HATCH; i++) {
        // NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Assign)
        uint32_t idx = indices[i];
        hypericum_adrs_set_fors_tree_height(adrs, 0);
        hypericum_adrs_set_fors_tree_index(adrs, i * t + idx);

        const uint8_t* sk = sig;
        hypericum_f(hash_algo, pk_seed, adrs, sk, roots_ptr);
        sig += HYPERICUM_N_BYTES;

        for (uint32_t j = 0; j < HYP_B; j++) {
            const uint8_t* auth = sig;
            hypericum_adrs_set_fors_tree_height(adrs, j + 1);
            if ((idx / (1u << j)) % 2 == 0) {
                hypericum_adrs_set_fors_tree_index(
                    adrs, hypericum_adrs_get_fors_tree_index(adrs) / 2);

                hypericum_h_node(
                    hash_algo, pk_seed, adrs, roots_ptr, auth, roots_ptr);
            } else {
                hypericum_adrs_set_fors_tree_index(
                    adrs, (hypericum_adrs_get_fors_tree_index(adrs) - 1) / 2);
                hypericum_h_node(
                    hash_algo, pk_seed, adrs, auth, roots_ptr, roots_ptr);
            }
            sig += HYPERICUM_N_BYTES;
        }
        roots_ptr += HYPERICUM_N_BYTES;
    }
    SECURE_ERASE(uint32_t, indices, HYP_K_HATCH);

    hypericum_adrs_set_type(adrs, address_fors_roots);
    hypericum_thk(hash_algo, pk_seed, adrs, roots, result);

    SECURE_ERASE(uint8_t, roots, HYP_K_HATCH * HYPERICUM_N_BYTES);
}
