
/*
 * Authors: Robert Ransom, Samuel Neves (ct_lt_u32 function)
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

/* constant-time comparison function by Samuel Neves, CC0, from
   https://gist.github.com/sneves/10845247 */

/* returns 1 if x < y, 0 otherwise */
static uint32_t ct_lt_u32(uint32_t x, uint32_t y)
{
    return (x^((x^y)|((x-y)^y)))>>31;
};


/* This should be modified to use a conditional move or swap operation
   on larger units than bytes, preferably a target-specific vectorized
   one if possible. */

static void blob_minmax(struct pkpsig_sort_blob *a, struct pkpsig_sort_blob *b, size_t value_bytes) {
  uint32_t swapmask = -ct_lt_u32(b->key, a->key);
  size_t i;
  uint8_t *abuf = a->value;
  uint8_t *bbuf = b->value;
  uint32_t keytmp = (a->key ^ b->key) & swapmask;
  a->key ^= keytmp;
  b->key ^= keytmp;

  for (i = 0; i < value_bytes; ++i) {
    uint8_t tmp = (abuf[i] ^ bbuf[i]) & swapmask;
    abuf[i] ^= tmp;
    bbuf[i] ^= tmp;
  };
};

