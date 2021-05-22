
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "randombytes.h"

/* copied from randombytes_shake256_deterministic.h for test purposes */
int randombytes(uint8_t *out, size_t len);

int pkpsig_randombytes(uint8_t *out, size_t len) {
    randombytes(out, len);
    return 0;
};

