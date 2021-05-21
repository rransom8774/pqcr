
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "randombytes.h"

/* copied from NIST rng.h for test purposes */
int
randombytes(unsigned char *x, unsigned long long xlen);

int pkpsig_randombytes(uint8_t *out, size_t len) {
    randombytes(out, len);
    return 0;
};

