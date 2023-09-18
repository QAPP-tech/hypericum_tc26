#include "xmssmt.h"

#include "xmss.h"
#include "adrs.h"
#include "utils.h"

#include <string.h>

const size_t N = HYPERICUM_N_BYTES;

// 'sk_seed' len: N
// 'pk_seed' len: N
// 'result' len: N
void hypericum_generate_xmssmt_pk(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    uint8_t* result)
{
    hypericum_adrs_t* adrs = hypericum_adrs_create();
    hypericum_adrs_set_layer_address(adrs, HYP_D - 1);
    hypericum_adrs_set_tree_address(adrs, 0);

    hypericum_xmss_pk(hash_algo, sk_seed, pk_seed, adrs, result);

    hypericum_adrs_destroy(adrs);
}

// 'sk_seed' len: N
// 'pk_seed' len: N
// 'msg' len: N
// 'result' len: `HYP_XMSSMT_BYTES`
void hypericum_sign_xmssmt(
    const hash_algo_t hash_algo,
    const uint8_t* sk_seed,
    const uint8_t* pk_seed,
    const uint8_t* msg,
    uint64_t idx_tree,
    uint32_t idx_leaf,
    uint8_t* result)
{
    hypericum_adrs_t* adrs = hypericum_adrs_create();
    hypericum_adrs_set_layer_address(adrs, 0);
    hypericum_adrs_set_tree_address(adrs, idx_tree);

    uint8_t* sig_tmp = result;
    const size_t sig_tmp_len = HYP_XMSSMT_BYTES / HYP_D;

    hypericum_xmss_sign(
        hash_algo, sk_seed, pk_seed, msg, idx_leaf, adrs, sig_tmp);

    ALLOC_ON_STACK(uint8_t, root, N);

    hypericum_xmss_pk_from_sig(
        hash_algo, pk_seed, msg, sig_tmp, idx_leaf, adrs, root);

    for (uint32_t j = 1; j < HYP_D; j++) {
        idx_leaf = idx_tree % (1ull << HYP_H_PRIME);
        idx_tree = idx_tree >> HYP_H_PRIME;
        hypericum_adrs_set_layer_address(adrs, j);
        hypericum_adrs_set_tree_address(adrs, idx_tree);

        sig_tmp += sig_tmp_len;
        hypericum_xmss_sign(
            hash_algo, sk_seed, pk_seed, root, idx_leaf, adrs, sig_tmp);

        if (j < HYP_D - 1) {
            hypericum_xmss_pk_from_sig(
                hash_algo, pk_seed, root, sig_tmp, idx_leaf, adrs, root);
        }
    }
    SECURE_ERASE(uint8_t, root, N);

    hypericum_adrs_destroy(adrs);
}

// 'pk_seed' len: N
// 'sig' len: `HYP_XMSSMT_BYTES`
// 'msg' len: N
// 'pk' len: N
int hypericum_verify_xmssmt(
    const hash_algo_t hash_algo,
    const uint8_t* pk_seed,
    const uint8_t* sig,
    const uint8_t* msg,
    uint64_t idx_tree,
    uint32_t idx_leaf,
    const uint8_t* pk)
{
    hypericum_adrs_t* adrs = hypericum_adrs_create();

    hypericum_adrs_set_layer_address(adrs, 0);
    hypericum_adrs_set_tree_address(adrs, idx_tree);

    uint8_t node[HYPERICUM_N_BYTES] = { 0 };

    hypericum_xmss_pk_from_sig(
        hash_algo, pk_seed, msg, sig, idx_leaf, adrs, node);

    const size_t sig_tmp_len = HYP_XMSSMT_BYTES / HYP_D;

    for (uint32_t j = 1; j < HYP_D; j++) {
        idx_leaf = idx_tree % (1ull << HYP_H_PRIME);
        idx_tree = idx_tree >> HYP_H_PRIME;
        const uint8_t* sig_tmp = sig + j * sig_tmp_len;
        hypericum_adrs_set_layer_address(adrs, j);
        hypericum_adrs_set_tree_address(adrs, idx_tree);
        hypericum_xmss_pk_from_sig(
            hash_algo, pk_seed, node, sig_tmp, idx_leaf, adrs, node);
    }

    int res = memcmp(node, pk, N);
    SECURE_ERASE(uint8_t, node, N);

    hypericum_adrs_destroy(adrs);

    return res == 0;
}
