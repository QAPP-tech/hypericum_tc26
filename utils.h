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
