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

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    unsigned char msg[] = "Hypericum";
    unsigned long long mlen = sizeof(msg);

    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];

    int ret;

    // private (or secret, sk) and public (pk) key pair generation.

    ret = crypto_sign_keypair(pk, sk);
    if (ret != 0) {
        printf("Error generating hypericum key pair\n");
        return ret;
    }
    printf("Hypericum key pair generated\n");

    // message signing. Private key is used for this operation.

    unsigned char* sm = calloc(CRYPTO_BYTES + mlen, sizeof(unsigned char));
    unsigned long long smlen;
    ret = crypto_sign(sm, &smlen, msg, mlen, sk);
    if (ret != 0) {
        printf("Error signing message\n");
        return ret;
    }
    printf("Hypericum Message signed\n");

    // signature verification. Public key is used for this
    // operation. Result will be 0 if signature correct.

    unsigned char* msg1 = calloc(mlen, sizeof(unsigned char));
    unsigned long long mlen1;
    ret = crypto_sign_open(msg1, &mlen1, sm, smlen, pk);

    if (!ret) {
        printf("Hypericum Signature is valid. Result is %d\n", ret);
    } else {
        printf("Hypericum Signature is invalid. Result is %d\n", ret);
    }

    free(sm);
    free(msg1);
    return ret;
}
