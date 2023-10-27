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
