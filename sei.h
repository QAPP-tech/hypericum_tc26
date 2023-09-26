#pragma once

#include <stdint.h>
#include <stddef.h>

#pragma once

#include "sei.h"

#include <stddef.h>

#define PQLR_SEI_RETRY_COUNT 3


/**
 * @brief Gets entropy via default entropy source
 *
 * Usage example:
 * \snippet common/snippets/get_sei.c get_sei_snippet
 * @param[out] data pointer to buffer where entropy will be written
 * @param size requested entropy size
 */
int get_hardware_entropy(void* data, size_t size);
