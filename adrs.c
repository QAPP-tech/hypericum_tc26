#include "adrs.h"
#include "utils.h"

#include <string.h>

struct hypericum_adrs_wots_hash
{
    uint32_t chain_address;
    uint32_t hash_address;
};

struct hypericum_adrs_tree
{
    uint32_t tree_height;
    uint32_t tree_index;
};

struct hypericum_adrs_keygen_fors
{
    uint32_t tree_height;
    uint32_t leaf_index;
};

struct hypericum_adrs_keygen_wots
{
    uint32_t chain_address;
};

struct _adrs
{
    uint32_t layer_address;
    uint32_t tree_address[2];
    enum address_type type;
    uint32_t keypair_address;

    union {
        struct hypericum_adrs_wots_hash wots_hash;
        struct hypericum_adrs_tree tree;
        struct hypericum_adrs_tree fors_tree;
        struct hypericum_adrs_keygen_wots keygen_wots;
        struct hypericum_adrs_keygen_fors keygen_fors;
        // wots_pk, fors_roots and msg_sign_wots are always zero
        uint8_t zeros[8];
    } data;
};

hypericum_adrs_t* hypericum_adrs_create()
{
    hypericum_adrs_t* res =
        (hypericum_adrs_t*)calloc(1, sizeof(hypericum_adrs_t));
    return res;
}

void hypericum_adrs_destroy(hypericum_adrs_t* adrs)
{
    if (adrs != NULL) {
        free(adrs);
    }
}

void hypericum_adrs_set_wots_hash_hash_address(
    hypericum_adrs_t* adrs, uint32_t value)
{
    adrs->data.wots_hash.hash_address = value;
}

void hypericum_adrs_set_wots_hash_chain_address(
    hypericum_adrs_t* adrs, uint32_t value)
{
    adrs->data.wots_hash.chain_address = value;
}

void hypericum_adrs_set_layer_address(hypericum_adrs_t* adrs, uint32_t value)
{
    adrs->layer_address = value;
}

// 64-bit tree_address is used instead of 96-bit because of
// ease of implementation and slight difference in safety.
void hypericum_adrs_set_tree_address(hypericum_adrs_t* adrs, uint64_t value)
{
    adrs->tree_address[0] = value >> 32;
    adrs->tree_address[1] = value & 0xFFFFFFFF;
}

void hypericum_adrs_set_type(hypericum_adrs_t* adrs, enum address_type value)
{
    adrs->type = value;

    if (value == address_tree) {
        hypericum_adrs_set_keypair_address(adrs, 0);
    }
}

enum address_type hypericum_adrs_get_type(const hypericum_adrs_t* adrs)
{
    return adrs->type;
}

void hypericum_adrs_set_tree_height(hypericum_adrs_t* adrs, uint32_t value)
{
    adrs->data.tree.tree_height = value;
}


uint32_t hypericum_adrs_get_tree_height(const hypericum_adrs_t* adrs)
{
    return adrs->data.tree.tree_height;
}


void hypericum_adrs_set_tree_index(hypericum_adrs_t* adrs, uint32_t value)
{
    adrs->data.tree.tree_index = value;
}


uint32_t hypericum_adrs_get_tree_index(const hypericum_adrs_t* adrs)
{
    return adrs->data.tree.tree_index;
}


void hypericum_adrs_set_keypair_address(hypericum_adrs_t* adrs, uint32_t value)
{
    adrs->keypair_address = value;
}

void hypericum_adrs_set_fors_tree_height(hypericum_adrs_t* adrs, uint32_t value)
{
    adrs->data.fors_tree.tree_height = value;
}


uint32_t hypericum_adrs_get_fors_tree_height(const hypericum_adrs_t* adrs)
{
    return adrs->data.fors_tree.tree_height;
}


void hypericum_adrs_set_fors_tree_index(hypericum_adrs_t* adrs, uint32_t value)
{
    adrs->data.fors_tree.tree_index = value;
}


uint32_t hypericum_adrs_get_fors_tree_index(const hypericum_adrs_t* adrs)
{
    return adrs->data.fors_tree.tree_index;
}

void hypericum_adrs_set_keygen_wots_chain_address(
    hypericum_adrs_t* adrs, uint32_t value)
{
    adrs->data.keygen_wots.chain_address = value;
}

static void fill_wots_hash(
    uint8_t* bytes, const struct hypericum_adrs_wots_hash* wots_hash)
{
    fill_bytes32(bytes, wots_hash->chain_address);
    fill_bytes32(bytes + 4, wots_hash->hash_address);
}

static void fill_tree(uint8_t* bytes, const struct hypericum_adrs_tree* tree)
{
    fill_bytes32(bytes, tree->tree_height);
    fill_bytes32(bytes + 4, tree->tree_index);
}

static void fill_keygen_fors(
    uint8_t* bytes, const struct hypericum_adrs_keygen_fors* tree)
{
    fill_bytes32(bytes, tree->tree_height);
    fill_bytes32(bytes + 4, tree->leaf_index);
}

static void fill_keygen_wots(
    uint8_t* bytes, const struct hypericum_adrs_keygen_wots* keygen_wots)
{
    fill_bytes32(bytes, keygen_wots->chain_address);
    memset(bytes + 4, 0, 4);
}

void hypericum_adrs_get_bytes(const hypericum_adrs_t* adrs, uint8_t* value)
{
    fill_bytes32(value, adrs->layer_address);
    fill_bytes32(value + 4, adrs->tree_address[0]);
    fill_bytes32(value + 8, adrs->tree_address[1]);
    fill_bytes32(value + 12, (uint32_t)adrs->type);
    fill_bytes32(value + 16, adrs->keypair_address);

    switch (adrs->type) {
        case address_wots_hash:
            fill_wots_hash(value + 20, &adrs->data.wots_hash);
            break;
        case address_wots_pk:
            memset(value + 20, 0, sizeof(adrs->data));
            break;
        case address_tree:
            fill_tree(value + 20, &adrs->data.tree);
            break;
        case address_fors_tree:
            fill_tree(value + 20, &adrs->data.fors_tree);
            break;
        case address_fors_roots:
            memset(value + 20, 0, sizeof(adrs->data));
            break;
        case address_sign_msg_wots:
            memset(value + 20, 0, sizeof(adrs->data));
            break;
        case address_keygen_wots:
            fill_keygen_wots(value + 20, &adrs->data.keygen_wots);
            break;
        case address_keygen_fors:
            fill_keygen_fors(value + 20, &adrs->data.keygen_fors);
            break;
    }
}

void hypericum_adrs_set_suffix(hypericum_adrs_t* adrs, uint64_t suffix)
{
    switch (adrs->type) {
        case address_wots_hash:
            adrs->data.wots_hash.chain_address = suffix >> 32;
            adrs->data.wots_hash.hash_address = suffix & 0xFFFFFFFF;
            break;
        case address_wots_pk:
            break;
        case address_sign_msg_wots:
            break;
        case address_tree:
            adrs->data.tree.tree_height = suffix >> 32;
            adrs->data.tree.tree_index = suffix & 0xFFFFFFFF;
            break;
        case address_fors_tree:
            adrs->data.fors_tree.tree_height = suffix >> 32;
            adrs->data.fors_tree.tree_index = suffix & 0xFFFFFFFF;
            break;
        case address_fors_roots:
            break;
        case address_keygen_wots:
            adrs->data.keygen_wots.chain_address = suffix;
            break;
        case address_keygen_fors:
            adrs->data.keygen_fors.tree_height = suffix >> 32;
            adrs->data.keygen_fors.leaf_index = suffix & 0xFFFFFFFF;
            break;
    }
}
