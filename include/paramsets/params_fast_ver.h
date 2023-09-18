#pragma once

#include <stdint.h>

/* Height of the hypertree. */
#define HYP_H 66
/* Hypertree layers count */
#define HYP_D 11
/* FORS+C tree height */
#define HYP_B 9
/* FORS+C trees count plus one */
#define HYP_K 38
/* Winternitz parameter */
#define HYP_W 4

static uint8_t md_suffix_nonzero(const uint8_t* digest)
{
    return (digest[41] & 0b00000111) | (digest[42] & 0b11111100);
}
