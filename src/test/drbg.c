
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "drbg.h"

#include <XKCP/SimpleFIPS202.h>

#include <assert.h>

static inline void pack_ui32(uint8_t *buf, uint32_t x) {
  buf[0] =  x        & 255;
  buf[1] = (x >>  8) & 255;
  buf[2] = (x >> 16) & 255;
  buf[3] = (x >> 24) & 255;
};

void drbg_init(struct drbg *drbg, uint8_t *seed, size_t seedlen) {
  SHAKE256(drbg->state, STATE_BYTES, seed, seedlen);
};

int drbg_run(struct drbg *drbg, uint8_t *out, size_t len) {
  size_t i = 0;
  uint8_t input[STATE_BYTES + 4];

  assert(sizeof(uint8_t) == 1);

  if (len != (size_t)(len & 0xFFFFFFFFUL)) {
    /* too big to be reasonable */
    return -1;
  };

  memcpy(input, drbg->state, STATE_BYTES);
  pack_ui32(input + STATE_BYTES, (uint32_t)len);

  while (i < len) {
    size_t blocklen = len - i;

    if (blocklen > GENBLOCK_BYTES) blocklen = GENBLOCK_BYTES;

    SHAKE256(drbg->genbuf, STATE_BYTES + blocklen, input, sizeof(input));
    memcpy(input, drbg->genbuf, STATE_BYTES);
    memcpy(out + i, drbg->genbuf + STATE_BYTES, blocklen);

    i += blocklen;
  };

  SHAKE256(drbg->state, STATE_BYTES, input, sizeof(input));

  return 0;
};

