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
