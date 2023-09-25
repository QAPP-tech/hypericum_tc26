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
