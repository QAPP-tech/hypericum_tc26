#include "sei_cryptoapi.h"

#ifdef WIN32
#include <windows.h>

uint8_t pqlr_get_entropy_from_cryptoapi(void* buf, size_t len)
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
