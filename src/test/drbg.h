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

#define STATE_BYTES 64
#define GENBLOCK_BYTES 2048
#define GENBUF_BYTES (GENBLOCK_BYTES+STATE_BYTES)

struct drbg {
  uint8_t state[STATE_BYTES];
  uint8_t genbuf[GENBUF_BYTES];
};

void drbg_init(struct drbg *drbg, uint8_t *seed, size_t seedlen);

int drbg_run(struct drbg *drbg, uint8_t *out, size_t len);

#endif
