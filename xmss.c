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

#include "params.h"
#include "xmss.h"
#include "wotsc.h"
#include "hash.h"
#include "utils.h"
#include "utils/intermediate.h"

#include "stack.h"

#include <string.h>


void hypericum_xmss_tree_hash(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    uint32_t start_index,
    uint32_t target_node_h,
    hypericum_adrs_t* adrs,
    uint8_t* result)
{
    stack_root_t* stack_root_node = NULL;
    for (uint32_t i = 0; i < (1u << target_node_h); i++) {
        hypericum_adrs_set_keypair_address(adrs, start_index + i);

        uint32_t node_h = 0;
        struct Node* node = hypericum_create_node(node_h);

        hypericum_generate_wots_pk(hash_algo, sk_seed, pk_seed, adrs, node->pk);

        hypericum_adrs_set_type(adrs, address_tree);
        hypericum_adrs_set_tree_height(adrs, 1);
        hypericum_adrs_set_tree_index(adrs, start_index + i);

        while (!stack_is_empty(stack_root_node) &&
               ((struct Node*)stack_peek(stack_root_node))->h == node_h) {
            hypericum_adrs_set_tree_index(
                adrs, (hypericum_adrs_get_tree_index(adrs) - 1) >> 1);

            struct Node* top_stack_node =
                (struct Node*)stack_pop(&stack_root_node);

            hypericum_h_node(
                hash_algo, pk_seed, adrs, top_stack_node->pk, node->pk,
                node->pk);

            secure_erase(top_stack_node->pk, HYPERICUM_N_BYTES);
            free(top_stack_node);

            node_h = hypericum_adrs_get_tree_height(adrs);
            hypericum_adrs_set_tree_height(adrs, node_h + 1);
        }
        node->h = node_h;
        stack_push(&stack_root_node, node);
    }

    struct Node* top_node = (struct Node*)stack_peek(stack_root_node);
    memcpy(result, top_node->pk, HYPERICUM_N_BYTES);

    // clear stack and free all the data if needed
    while (!stack_is_empty(stack_root_node)) {
        struct Node* node = (struct Node*)stack_pop(&stack_root_node);
        secure_erase(node->pk, HYPERICUM_N_BYTES);
        free(node);
    }
}


void hypericum_xmss_pk(
    const hash_algo_t hash_algo,
    const void* sk_seed,
    const void* pk_seed,
    hypericum_adrs_t* adrs,
    uint8_t* result)
{
    hypericum_xmss_tree_hash(
        hash_algo, sk_seed, pk_seed, 0, HYP_H_PRIME, adrs, result);
}


void hypericum_xmss_sign(
    const hash_algo_t hash_algo,
    const void* sk_seed,
    const void* pk_seed,
    const uint8_t* msg,
    uint32_t idx,
    hypericum_adrs_t* adrs,
    uint8_t* result)
{
    // build auth path
    uint8_t* auth = result + HYP_WOTS_BYTES;

    for (uint32_t j = 0; j < HYP_H_PRIME; j++) {
        uint32_t k = ((idx >> j) ^ 1);
        hypericum_xmss_tree_hash(
            hash_algo, sk_seed, pk_seed, k * (1u << j), j, adrs,
            auth + j * HYPERICUM_N_BYTES);
    }
    hypericum_adrs_set_type(adrs, address_wots_hash);
    hypericum_adrs_set_keypair_address(adrs, idx);
    hypericum_sign_wots(hash_algo, msg, sk_seed, pk_seed, adrs, result);
}


void hypericum_xmss_pk_from_sig(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const uint8_t* msg,
    const uint8_t* sig,
    uint32_t idx,
    hypericum_adrs_t* adrs,
    uint8_t* result)
{
    hypericum_adrs_set_keypair_address(adrs, idx);

    uint8_t* auth = (uint8_t*)sig + HYP_WOTS_BYTES;
    hypericum_generate_wots_pk_from_sig(
        hash_algo, sig, msg, pk_seed, adrs, result);

    INTERMEDIATE_OUTPUT(print_verify_wots_pk(result));

    hypericum_adrs_set_type(adrs, address_tree);
    hypericum_adrs_set_tree_index(adrs, idx);
    for (uint32_t k = 0; k < HYP_H_PRIME; k++) {
        hypericum_adrs_set_tree_height(adrs, k + 1);
        if ((idx >> k) % 2 == 0) {
            hypericum_adrs_set_tree_index(
                adrs, hypericum_adrs_get_tree_index(adrs) >> 1);
            hypericum_h_node(
                hash_algo, pk_seed, adrs, result, auth + k * HYPERICUM_N_BYTES,
                result);
        } else {
            hypericum_adrs_set_tree_index(
                adrs, (hypericum_adrs_get_tree_index(adrs) - 1) >> 1);
            hypericum_h_node(
                hash_algo, pk_seed, adrs, auth + k * HYPERICUM_N_BYTES, result,
                result);
        }
    }
}
