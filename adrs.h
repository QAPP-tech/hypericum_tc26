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

#include <stdint.h>
#include <stddef.h>

#define HYPERICUM_ADRS_SIZE_BYTES 28

enum address_type {
    address_wots_hash = 0,
    address_wots_pk = 1,
    address_tree = 2,
    address_fors_tree = 3,
    address_fors_roots = 4,
    address_sign_msg_wots = 5,
    address_keygen_wots = 6,
    address_keygen_fors = 7
};

typedef struct _adrs hypericum_adrs_t;

hypericum_adrs_t* hypericum_adrs_create();
void hypericum_adrs_destroy(hypericum_adrs_t* adrs);

void hypericum_adrs_set_wots_hash_hash_address(
    hypericum_adrs_t* adrs, uint32_t value);

void hypericum_adrs_set_wots_hash_chain_address(
    hypericum_adrs_t* adrs, uint32_t value);

void hypericum_adrs_set_layer_address(hypericum_adrs_t* adrs, uint32_t value);

// 64-bit tree_address is used instead of 96-bit because of
// ease of implementation and slight difference in safety.
void hypericum_adrs_set_tree_address(hypericum_adrs_t* adrs, uint64_t value);

void hypericum_adrs_set_type(hypericum_adrs_t* adrs, enum address_type value);
enum address_type hypericum_adrs_get_type(const hypericum_adrs_t* adrs);

void hypericum_adrs_set_tree_height(hypericum_adrs_t* adrs, uint32_t value);

uint32_t hypericum_adrs_get_tree_height(const hypericum_adrs_t* adrs);


void hypericum_adrs_set_tree_index(hypericum_adrs_t* adrs, uint32_t value);

uint32_t hypericum_adrs_get_tree_index(const hypericum_adrs_t* adrs);

void hypericum_adrs_set_keypair_address(hypericum_adrs_t* adrs, uint32_t value);

void hypericum_adrs_set_fors_tree_height(
    hypericum_adrs_t* adrs, uint32_t value);

uint32_t hypericum_adrs_get_fors_tree_height(const hypericum_adrs_t* adrs);

void hypericum_adrs_set_fors_tree_index(hypericum_adrs_t* adrs, uint32_t value);

uint32_t hypericum_adrs_get_fors_tree_index(const hypericum_adrs_t* adrs);

void hypericum_adrs_set_keygen_wots_chain_address(
    hypericum_adrs_t* adrs, uint32_t value);

void hypericum_adrs_get_bytes(const hypericum_adrs_t* adrs, uint8_t* value);

void hypericum_adrs_set_suffix(hypericum_adrs_t* adrs, uint64_t suffix);
