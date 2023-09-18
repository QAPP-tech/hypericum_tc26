#pragma once

#include <stdint.h>

/* Height of the hypertree. */
#define HYP_H 70
/* Hypertree layers count */
#define HYP_D 7
/* FORS+C tree height */
#define HYP_B 17
/* FORS+C trees count plus one */
#define HYP_K 14
/* Winternitz parameter */
#define HYP_W 256

static uint8_t md_suffix_nonzero(const uint8_t* digest)
{
    return (digest[27] & 0b00000111) | digest[28] | (digest[29] & 0b11111100);
}
