#pragma once

#include <stdint.h>
#include <stddef.h>


/**
 * @brief Get entropy using CryptoAPI.
 *
 * Available on Windows.
 *
 * This function should NEVER be used directly. The correct usage example is:
 * \snippet common/snippets/get_sei.c
 * get_entropy_from_cryptoapi_snippet
 * @param[out] buf Preallocated empty buffer, used to return entropy.
 * @param len Requested entropy length in bytes.
 *   Must be less or equal length of buffer pointed by buf.
 * @returns 0 on success, 1 on failure
 */
uint8_t pqlr_get_entropy_from_cryptoapi(void* buf, size_t len);
