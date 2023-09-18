#pragma once

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>

#include "params.h"

#ifdef WIN32
#include <malloc.h>
// WARNING: Do not use it within loops! It can be used only within function
// scope.
#define ALLOC_ON_STACK(type, name, len) \
    type* name = (type*)_alloca((len) * sizeof(type));
#else  // WIN32
// WARNING: Do not use it within loops! It can be used only within function
// scope.
#define ALLOC_ON_STACK(type, name, len) type name[len];
#endif  // WIN32

#define SECURE_ERASE(type, name, len) secure_erase(name, (len) * sizeof(type));

void secure_erase(void* buf, size_t len);

// data structure and functions for *_tree_hash algoritm

struct Node
{
    uint8_t pk[HYPERICUM_N_BYTES];
    uint32_t h;
};

struct Node* hypericum_create_node(uint32_t h);
