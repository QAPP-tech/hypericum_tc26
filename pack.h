#pragma once

#include "params.h"

#include <stdint.h>

typedef struct
{
    uint8_t* seed;
    uint8_t* root;
} hypericum_pk_internal_t;

hypericum_pk_internal_t hypericum_pk_parse(uint8_t* pk);


typedef struct
{
    uint8_t* seed;
    uint8_t* prf;
    hypericum_pk_internal_t pk;
} hypericum_sk_internal_t;

hypericum_sk_internal_t hypericum_sk_parse(uint8_t* sk);

typedef struct
{
    uint8_t* r;
    uint8_t* s;
    uint8_t* sig_fors;
    uint8_t* sig_ht;

} hypericum_sig_internal_t;

hypericum_sig_internal_t hypericum_sig_parse(uint8_t* sig);
