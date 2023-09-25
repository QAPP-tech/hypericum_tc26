#pragma once

#include <stdint.h>
#include <stddef.h>

#define HYPERICUM_ADRS_SIZE_BYTES 28

enum address_type {
    address_wots_hash = 0,
    address_wots_pk = 1,
    address_tree = 2,
    address_fors_tree = 3,
    address_fors_roots = 4,
    address_sign_msg_wots = 5,
    address_keygen_wots = 6,
    address_keygen_fors = 7
};

typedef struct _adrs hypericum_adrs_t;

hypericum_adrs_t* hypericum_adrs_create();
void hypericum_adrs_destroy(hypericum_adrs_t* adrs);

void hypericum_adrs_set_wots_hash_hash_address(
    hypericum_adrs_t* adrs, uint32_t value);

void hypericum_adrs_set_wots_hash_chain_address(
    hypericum_adrs_t* adrs, uint32_t value);

void hypericum_adrs_set_layer_address(hypericum_adrs_t* adrs, uint32_t value);

// 64-bit tree_address is used instead of 96-bit because of
// ease of implementation and slight difference in safety.
void hypericum_adrs_set_tree_address(hypericum_adrs_t* adrs, uint64_t value);

void hypericum_adrs_set_type(hypericum_adrs_t* adrs, enum address_type value);
enum address_type hypericum_adrs_get_type(const hypericum_adrs_t* adrs);

void hypericum_adrs_set_tree_height(hypericum_adrs_t* adrs, uint32_t value);

uint32_t hypericum_adrs_get_tree_height(const hypericum_adrs_t* adrs);


void hypericum_adrs_set_tree_index(hypericum_adrs_t* adrs, uint32_t value);

uint32_t hypericum_adrs_get_tree_index(const hypericum_adrs_t* adrs);

void hypericum_adrs_set_keypair_address(hypericum_adrs_t* adrs, uint32_t value);

void hypericum_adrs_set_fors_tree_height(
    hypericum_adrs_t* adrs, uint32_t value);

uint32_t hypericum_adrs_get_fors_tree_height(const hypericum_adrs_t* adrs);

void hypericum_adrs_set_fors_tree_index(hypericum_adrs_t* adrs, uint32_t value);

uint32_t hypericum_adrs_get_fors_tree_index(const hypericum_adrs_t* adrs);

void hypericum_adrs_set_keygen_wots_chain_address(
    hypericum_adrs_t* adrs, uint32_t value);

void hypericum_adrs_get_bytes(const hypericum_adrs_t* adrs, uint8_t* value);

void hypericum_adrs_set_suffix(hypericum_adrs_t* adrs, uint64_t suffix);
