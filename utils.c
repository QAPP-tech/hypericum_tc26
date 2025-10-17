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

#include "utils.h"

void secure_erase(void* buf, size_t len)
{
#if (__STDC_VERSION__ >= 201112L) && __STDC_LIB_EXT1__
    memset_s(buf, len, 0, len);
#else
    volatile uint8_t* p = buf;
    while (len--) {
        *p++ = 0;
    }
#endif  // (__STDC_VERSION__ >= 201112L) && __STDC_LIB_EXT1__
}

struct Node* hypericum_create_node(uint32_t h)
{
    struct Node* node = (struct Node*)calloc(1, sizeof(struct Node));
    if (NULL == node) {
        return NULL;
    }

    node->h = h;

    return node;
}

void fill_bytes32(uint8_t* bytes, uint32_t value)
{
    bytes[0] = value & 0xFF;
    bytes[1] = (value >> 8) & 0xFF;
    bytes[2] = (value >> 16) & 0xFF;
    bytes[3] = (value >> 24) & 0xFF;
}

uint32_t fill_uint32(const uint8_t* bytes)
{
    uint64_t ret = 0;
    for (uint32_t i = 4; i > 0; --i) {
        ret = (ret << 8) | bytes[i - 1];
    }
    return ret;
}

uint64_t fill_uint64(const uint8_t* bytes)
{
    uint64_t ret = 0;
    for (uint32_t i = 8; i > 0; --i) {
        ret = (ret << 8) | bytes[i - 1];
    }
    return ret;
}

