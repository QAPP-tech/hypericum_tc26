#include <stdint.h>
#include <stdio.h>

#include "intermediate.h"
#include "api.h"
#include "../pack.h"

static uint8_t wots_pk_output_enabled = 1;

void print_hex(const char *label, const uint8_t *data, unsigned long long data_len)
{
    printf("%s: ", label);
    for (long long i = 0; i < data_len; ++i)
    {
        printf("0x%02x ", data[i]);
    }
    printf("\n\n");
}

void print_sign_randomization_parameters(const hypericum_sig_internal_t *sig)
{
    printf("opt_const: %s\n\n", HYPERICUM_OPT);
    print_hex("R", sig->r, HYPERICUM_N_BYTES);
}

void print_sign_preparation_data(const uint8_t *s, const uint8_t *digest, uint64_t idx_tree, uint32_t idx_leaf)
{
    print_hex("s", s, 4);
    print_hex("digest", digest, 64);
    printf("idx_tree: %llu\n\n", idx_tree);
    printf("idx_leaf: %u\n\n", idx_leaf);
}

void print_sign_fors(const hypericum_sig_internal_t *sig)
{
    print_hex("SIG_FORS", sig->sig_fors, HYP_FORSC_BYTES);
}

void print_sign_ht(uint32_t layer, const uint8_t *ht_layer_sig) {
    if (layer == 0) {
        printf("SIG_HT:\n");
    }
    printf("\tlayer %d: ", layer);
    for (long long i = 0; i < HYP_XMSSMT_BYTES / HYP_D; ++i) {
        printf("0x%02x ", ht_layer_sig[i]);
    }
    printf("\n");
    if (layer == HYP_D - 1) {
        printf("\n");
    }
}

void print_verify_parsed_signature(const hypericum_sig_internal_t *sig)
{
    print_hex("R", sig->r, HYPERICUM_N_BYTES);
    print_hex("s", sig->s, 4);
    print_hex("SIG_FORS (extracted)", sig->sig_fors, HYP_FORSC_BYTES);
    print_hex("SIG_HT (extracted)", sig->sig_ht, HYP_XMSSMT_BYTES);
}

void print_verify_hash_data(const uint8_t *digest, uint64_t idx_tree, uint32_t idx_leaf)
{
    print_hex("digest", digest, 64);
    printf("idx_tree: %llu\n\n", idx_tree);
    printf("idx_leaf: %u\n\n", idx_leaf);
}
void print_verify_pk_fors(const uint8_t *pk_fors)
{
    print_hex("PK_FORS", pk_fors, HYPERICUM_N_BYTES);
}

void print_verify_xmss_pk(const uint8_t *xmss_pk)
{
    print_hex("XMSS_PK", xmss_pk, HYPERICUM_N_BYTES);
}

void print_verify_wots_pk(const uint8_t *wots_pk)
{
    if (wots_pk_output_enabled)
    {
        print_hex("WOTS_PK", wots_pk, HYPERICUM_N_BYTES);
    }
}

void print_verify_pk_root(const uint8_t *pk)
{
    print_hex("PK.root", pk, HYPERICUM_N_BYTES);
}

void print_verify_layer(uint32_t layer)
{
    printf("========== LAYER %d ==========\n", layer);
}

void print_sk(const hypericum_sk_internal_t *sk)
{
    print_hex("SK.seed", sk->seed, HYPERICUM_N_BYTES);
    print_hex("SK.prf", sk->prf, HYPERICUM_N_BYTES);
}

void print_pk(const hypericum_pk_internal_t *pk)
{
    print_hex("PK.seed", pk->seed, HYPERICUM_N_BYTES);
    print_hex("PK.root", pk->root, HYPERICUM_N_BYTES);
}

void disable_wots_pk_output()
{
    wots_pk_output_enabled = 0;
}

void enable_wots_pk_output()
{
    wots_pk_output_enabled = 1;
}
