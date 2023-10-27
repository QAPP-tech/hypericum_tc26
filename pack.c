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

#include "pack.h"
#include "params.h"

hypericum_pk_internal_t hypericum_pk_parse(uint8_t* pk)
{
    hypericum_pk_internal_t pk_parsed = { .seed = pk,
                                          .root = pk + HYPERICUM_N_BYTES };
    return pk_parsed;
}

hypericum_sk_internal_t hypericum_sk_parse(uint8_t* sk)
{
    hypericum_sk_internal_t sk_parsed = { .seed = sk,
                                          .prf = sk + HYPERICUM_N_BYTES,
                                          .pk = hypericum_pk_parse(
                                              sk + HYPERICUM_N_BYTES * 2) };
    return sk_parsed;
}

hypericum_sig_internal_t hypericum_sig_parse(uint8_t* sig)
{
    hypericum_sig_internal_t sig_parsed;

    sig_parsed.r = sig;
    sig += HYPERICUM_N_BYTES;

    sig_parsed.s = sig;
    sig += 4;

    sig_parsed.sig_fors = sig;
    sig += HYP_FORSC_BYTES;

    sig_parsed.sig_ht = sig;

    return sig_parsed;
}
