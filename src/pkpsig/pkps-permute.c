
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "permute.h"

#include "paramset.h"
#include "sort.h"
#include "symmetric.h"

#include <assert.h>

void pkpsig_permute_prepare(struct pkpsig_scratch_store *st) {
  size_t n = st->ps->pkpparams->n;
  pkpsig_sort_posint32_pad_sortbuf(st->vecbuf, n);
};

void pkpsig_permute_apply_inv(struct pkpsig_scratch_store *st, uint16_t *v_sigma, const uint16_t *v, const uint8_t *sigma_inv) {
  size_t n = st->ps->pkpparams->n;
  size_t n_padlen = st->ps->pkpparams->n_padlen;
  size_t i;
  uint32_t *vecbuf = st->vecbuf;

  for (i = 0; i < n; ++i) {
    uint32_t si_i = sigma_inv[i];
    uint32_t v_i = v[i];
    vecbuf[i] = v_i | (si_i << 16);
  };

  pkpsig_sort_posint32(vecbuf, n_padlen);

  for (i = 0; i < n; ++i) {
    v_sigma[i] = vecbuf[i] & 0xFFFF;
  };
};

void pkpsig_permute_apply_and_compose_inv(struct pkpsig_scratch_store *st, uint16_t *v_sigma, uint8_t *pi_sigma, const uint16_t *v, const uint8_t *pi, const uint8_t *sigma_inv) {
  size_t n = st->ps->pkpparams->n;
  size_t n_padlen = st->ps->pkpparams->n_padlen;
  size_t i;
  uint32_t *vecbuf = st->vecbuf;

  assert(n <= 128);

  for (i = 0; i < n; ++i) {
    uint32_t si_i = sigma_inv[i];
    uint32_t p_i = pi[i];
    uint32_t v_i = v[i];
    vecbuf[i] = v_i | (p_i << 16) | (si_i << 24);
  };

  pkpsig_sort_posint32(vecbuf, n_padlen);

  for (i = 0; i < n; ++i) {
    v_sigma[i] = vecbuf[i] & 0xFFFF;
    pi_sigma[i] = (vecbuf[i] >> 16) & 0xFF;
  };
};

void pkpsig_perm_squish(struct pkpsig_scratch_store *st, uint8_t *sigma) {
  size_t n = st->ps->pkpparams->n;
  size_t i, j;

  for (i = 0; i < n; ++i) {
    uint8_t s_i = sigma[i];
    for (j = i+1; j < n; ++j) {
      if (sigma[j] > s_i) --(sigma[j]);
    };
  };

  assert(sigma[n-1] == 0);
};

void pkpsig_perm_unsquish(struct pkpsig_scratch_store *st, uint8_t *sigma) {
  size_t n = st->ps->pkpparams->n;
  size_t i, j;

  sigma[n-1] = 0;

  i = n;
  while (i != 0) {
    uint8_t s_i;
    --i;
    s_i = sigma[i];
    for (j = i+1; j < n; ++j) {
      if (sigma[j] >= s_i) ++(sigma[j]);
    };
  };
};

