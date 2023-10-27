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

#include "sei_urandom.h"

#include <stdio.h>


uint8_t get_entropy_from_urandom(void* buf, size_t len)
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
