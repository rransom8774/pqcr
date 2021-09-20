
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "randombytes_shake256_deterministic.h"

#include <XKCP/SimpleFIPS202.h>

#include <assert.h>

#define STATE_BYTES 64
#define GENBLOCK_BYTES 2048
#define GENBUF_BYTES (GENBLOCK_BYTES+STATE_BYTES)

static uint8_t state[STATE_BYTES];
static uint8_t genbuf[GENBUF_BYTES];

static inline void pack_ui32(uint8_t *buf, uint32_t x) {
  buf[0] =  x        & 255;
  buf[1] = (x >>  8) & 255;
  buf[2] = (x >> 16) & 255;
  buf[3] = (x >> 24) & 255;
};

void randombytes_shake256_det_init(uint8_t *seed, size_t seedlen) {
  SHAKE256(state, STATE_BYTES, seed, seedlen);
};

int randombytes(uint8_t *out, size_t len) {
  size_t i = 0;
  uint8_t input[STATE_BYTES + 4];

  assert(sizeof(uint8_t) == 1);

  if (len != (size_t)(len & 0xFFFFFFFFUL)) {
    /* too big to be reasonable */
    return -1;
  };

  memcpy(input, state, STATE_BYTES);
  pack_ui32(input + STATE_BYTES, (uint32_t)len);

  while (i < len) {
    size_t blocklen = len - i;

    if (blocklen > GENBLOCK_BYTES) blocklen = GENBLOCK_BYTES;

    SHAKE256(genbuf, STATE_BYTES + blocklen, input, sizeof(input));
    memcpy(input, genbuf, STATE_BYTES);
    memcpy(out + i, genbuf + STATE_BYTES, blocklen);

    i += blocklen;
  };

  SHAKE256(state, STATE_BYTES, input, sizeof(input));

  return 0;
};

