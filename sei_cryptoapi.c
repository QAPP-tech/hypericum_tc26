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

#include "sei_cryptoapi.h"

#ifdef WIN32
#include <windows.h>

uint8_t get_entropy_from_cryptoapi(void* buf, size_t len)
{
    HCRYPTPROV hProvider = (HCRYPTPROV)NULL;

    if (!CryptAcquireContext(
            &hProvider, NULL, NULL, PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return 1;
    }

    DWORD length = (DWORD)len;
    BYTE* buffer = (BYTE*)buf;

    // CryptGenRandom has a DWORD length argument, which is unsigned long (32
    // bits), so if len is 64-bit and is bigger than ULONG_MAX, perform 2-step
    // generation
    if (sizeof(size_t) > sizeof(DWORD) && len > ULONG_MAX) {
        if (!CryptGenRandom(hProvider, ULONG_MAX, buffer)) {
            return 1;
        }
        length = (DWORD)(len - ULONG_MAX);
        buffer += ULONG_MAX;
    }

    if (!CryptGenRandom(hProvider, length, buffer)) {
        return 1;
    }
    if (!CryptReleaseContext(hProvider, 0)) {
        return 1;
    }
    return 0;
}

#endif  // WIN32
