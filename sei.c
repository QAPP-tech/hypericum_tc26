#include "sei.h"

#ifdef WIN32
#include "sei_cryptoapi.h"
#else
#include "sei_urandom.h"
#endif  // WIN32

#include <string.h>


int get_hardware_entropy(void* data, size_t size)
{
    size_t retry_count = PQLR_SEI_RETRY_COUNT;
    while (retry_count > 0) {
        if (0 ==
#ifdef WIN32
            pqlr_get_entropy_from_cryptoapi(data, size)
#else
            pqlr_get_entropy_from_urandom(data, size)
#endif  // WIN32
        ) {
            return 0;
        }
        retry_count--;
    }
    return 1;
}
