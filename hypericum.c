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

#include "api.h"
#include "sign.h"

#include <string.h>

// 'result_sk' len: hyp_sk_bytes
// 'result_pk' len: hyp_pk_bytes
int crypto_sign_keypair(uint8_t* pk, uint8_t* sk)
{
    return hypericum_generate_keys(sk, pk);
}

int crypto_sign(
    unsigned char* sm,
    unsigned long long* smlen,
    const unsigned char* m,
    unsigned long long mlen,
    const unsigned char* sk)
{
    unsigned long long i;
    for (i = mlen; i > 0; i--) {
        sm[HYP_SIGNATURE_BYTES + i - 1] = m[i - 1];
    }
    *smlen = HYP_SIGNATURE_BYTES + mlen;
    return hypericum_sign(sk, m, mlen, sm);
}

int crypto_sign_open(
    unsigned char* m,
    unsigned long long* mlen,
    const unsigned char* sm,
    unsigned long long smlen,
    const unsigned char* pk)
{
    *mlen = smlen - HYP_SIGNATURE_BYTES;

    memcpy(m, sm + HYP_SIGNATURE_BYTES, *mlen);
    return hypericum_verify(pk, sm, m, *mlen);
}
