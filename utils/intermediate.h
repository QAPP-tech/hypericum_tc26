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

#ifdef WITH_INTERMEDIATE_OUTPUT
#define INTERMEDIATE_OUTPUT(arg) (arg)
#else
#define INTERMEDIATE_OUTPUT(arg) /*noop*/
#endif

#ifdef WITH_INTERMEDIATE_OUTPUT

#include "../pack.h"

void print_sk(const hypericum_sk_internal_t *sk);

void print_pk(const hypericum_pk_internal_t *pk);

void print_sign_randomization_parameters(const hypericum_sig_internal_t *sig);

void print_sign_fors(const hypericum_sig_internal_t *sig);

void print_sign_ht(uint32_t layer, const uint8_t *ht_layer_sig);

void print_sign_preparation_data(const uint8_t *s, const uint8_t *digest, uint64_t idx_tree, uint32_t idx_leaf);

void print_verify_parsed_signature(const hypericum_sig_internal_t *sig);

void print_verify_hash_data(const uint8_t *digest, uint64_t idx_tree, uint32_t idx_leaf);

void print_verify_pk_fors(const uint8_t *pk_fors);

void print_verify_xmss_pk(const uint8_t *xmss_pk);

void print_verify_wots_pk(const uint8_t *wots_pk);

void print_verify_pk_root(const uint8_t *pk);

void print_verify_layer(uint32_t layer);

void print_hex(const char *label, const uint8_t *data, unsigned long long data_len);

void disable_wots_pk_output();

void enable_wots_pk_output();

#endif


