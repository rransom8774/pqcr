
/*
 * Authors: Robert Ransom, Samuel Neves (ct_lt_u32 and ct_ge_u32 functions)
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "paramset.h"
#include "modulo.h"
#include "keys.h"
#include "symmetric.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* constant-time comparison functions by Samuel Neves, CC0, from
   https://gist.github.com/sneves/10845247 */

/* returns 1 if x < y, 0 otherwise */
static uint32_t ct_lt_u32(uint32_t x, uint32_t y)
{
    return (x^((x^y)|((x-y)^y)))>>31;
};

static uint32_t ct_ge_u32(uint32_t x, uint32_t y)
{
    return 1 ^ ct_lt_u32(x, y);
}

struct encode_alphabet_entry {
  uint8_t value;
  char ch;
};

static const struct encode_alphabet_entry base34_map[] =
  { { 0, 'a' },
    { 11, 'L' },
    { 12, 'm' },
    { 26, '2' } };

static char encode_base34_digit(int digit) {
  static const size_t base34_map_len = sizeof(base34_map)/sizeof(base34_map[0]);
  size_t i;
  int offset;

  assert(base34_map[0].value == 0);
  offset = base34_map[0].ch;

  for (i = 0; i < base34_map_len; ++i) {
    uint32_t is_above_bound = ct_ge_u32(digit, base34_map[i].value);
    int mask = (int)(-is_above_bound);

    offset = ((((int)(base34_map[i].ch) - (int)(base34_map[i].value)) & mask) |
              (offset & (~mask)));
  };

  return digit + offset;
};

#define VECTOR_ENCODE_LIMIT 16384

static void encode_vector_element(const struct modulus *outmod, uint32_t limit, uint8_t **pS, uint32_t *pr, uint32_t *pm) {
  uint8_t *S = *pS;
  uint32_t r = *pr;
  uint32_t m = *pm;

  /* output "bytes" */
  while (m >= limit) {
    uint32_t rem;
    uint32_t quot = pqcr_modulus_divmod(outmod, &rem, r);
    *S = rem; ++S;
    r = quot;
    m = pqcr_modulus_divide(outmod, m + (outmod->orig - 1));
  };

  *pS = S;
  *pr = r;
  *pm = m;
};

static size_t encode_vector_layer(const struct modulus *outmod, uint8_t **pS, uint32_t *R, uint32_t *M, size_t len) {
  size_t i, j;

  for (i = 0, j = 0; i < len - 1; i += 2, j += 1) {
    uint32_t r = R[i] + M[i]*R[i+1];
    uint32_t m = M[i] * M[i+1];

    encode_vector_element(outmod, VECTOR_ENCODE_LIMIT, pS, &r, &m);

    R[j] = r;
    M[j] = m;
  };

  if ((len & 1) != 0) {
    R[j] = R[i];
    M[j] = M[i];
    ++j;
  };

  return j;
};

static void base34_fingerprint(struct pkpsig_scratch_store *st, uint8_t *out, const uint8_t *hash) {
  struct modulus outmod_, *outmod = &outmod_;
  size_t bytes_fingerprint = st->ps->keyfmt->bytes_seckeyseed;
  size_t i;
  uint32_t *Rbuf = st->vecbuf;
  uint32_t *Mbuf = st->vecbuf + bytes_fingerprint;
  size_t veclen = bytes_fingerprint;

  if (pqcr_modulus_init(outmod, 34) != 0) abort();

  for (i = 0; i < bytes_fingerprint; ++i) {
    Rbuf[i] = hash[i];
    Mbuf[i] = 256;
  };

  while (veclen > 1) {
    veclen = encode_vector_layer(outmod, &out, Rbuf, Mbuf, veclen);
  };

  encode_vector_element(outmod, 2, &out, Rbuf, Mbuf);
};

void pkpsig_format_fingerprint(struct pkpsig_scratch_store *st, char *out, const uint8_t *hash) {
  uint8_t *digits = st->tmpbuf;
  const pkpsig_fprint_line_format *fprint_fmt =
    st->ps->keyfmt->fingerprint_format;
  size_t k, j, i;

  base34_fingerprint(st, digits, hash);

  for (k = 0; fprint_fmt[k] != NULL; ++k) {
    const uint8_t *line_fmt = fprint_fmt[k];
    for (j = 0; line_fmt[j] != 0; ++j) {
      for (i = 0; i < line_fmt[j]; ++i) {
        *out = encode_base34_digit(*digits);
        ++out; ++digits;
      };

      if (line_fmt[j+1] != 0) {
        *out = ' ';
        ++out;
      };
    };

    *out = '\n';
    ++out;
  };

  /* remove trailing \n and NUL-terminate */
  --out;
  *out = 0;
};

void pkpsig_key_fingerprint(struct pkpsig_scratch_store *st, struct pkpsig_keypublic *pub, char *out) {
  uint8_t *hash = st->outputbuf;
  size_t bytes_pkblob = pkpsig_paramset_get_pkblob_bytes(st->ps);

  assert(st->ps == pub->kp.ps);

  pkpsig_symmetric_gen_fingerprint_hash(st, hash, pub->pkblob, bytes_pkblob);
  pkpsig_format_fingerprint(st, out, hash);
};

