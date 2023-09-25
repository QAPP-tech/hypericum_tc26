#include "sei_urandom.h"

#include <stdio.h>


uint8_t pqlr_get_entropy_from_urandom(void* buf, size_t len)
{
    FILE* urandom_fd = NULL;

    if (urandom_fd == NULL) {
        urandom_fd = fopen("/dev/urandom", "r");
        if (urandom_fd == NULL) {
            return 1;
        }
        if (setvbuf(urandom_fd, NULL, _IONBF, 0) != 0) {
            if (fclose(urandom_fd) != 0) {
                return 1;
            }
            return 1;
        }
    }

    // /dev/urandom never blocks and always fills in as many bytes as you've
    // requested, unless the system call is interrupted by a signal
    if (fread(buf, 1, len, urandom_fd) != len) {
        return 1;
    }

    if (urandom_fd == NULL) {
        return 1;
    }
    if (fclose(urandom_fd) != 0) {
        return 1;
    }

    return 0;
}
