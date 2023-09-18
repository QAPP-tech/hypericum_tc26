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
