#ifndef X0tk5i1xiyg6w2ypxhpr6hqnbxbrin7bakggl94mmhg7dmqi042xhgoincurc96cj
#define X0tk5i1xiyg6w2ypxhpr6hqnbxbrin7bakggl94mmhg7dmqi042xhgoincurc96cj

/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include <stddef.h>
#include <stdint.h>

#define TESTVEC_RANDOMBYTES_IMPL_NAME "SHAKE256"

void randombytes_shake256_det_init(uint8_t *seed, size_t seedlen);

int randombytes(uint8_t *out, size_t len);

#endif
