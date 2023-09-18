#pragma once

#include <stdint.h>

/* Height of the hypertree. */
#define HYP_H 66
/* Hypertree layers count */
#define HYP_D 22
/* FORS+C tree height */
#define HYP_B 9
/* FORS+C trees count plus one */
#define HYP_K 36
/* Winternitz parameter */
#define HYP_W 16

static uint8_t md_suffix_nonzero(const uint8_t* digest)
{
    return (digest[39] & 0b00011111) | (digest[40] & 0b11110000);
}
