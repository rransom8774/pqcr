
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "randombytes.h"

/* prototype copied from "../ssh.h" */
void random_read(void *out, size_t size);

int pkpsig_randombytes(uint8_t *out, size_t len) {
    random_read(out, len);
    return 0;
};

