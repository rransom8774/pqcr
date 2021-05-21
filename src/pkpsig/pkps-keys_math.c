
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "keys.h"
#include "modulo.h"
#include "paramset.h"
#include "symmetric.h"

void pkpsig_mult_vec_by_A(struct pkpsig_scratch_store *st, struct pkpsig_keyparams *kp, uint16_t *out, const uint16_t *w) {
  size_t i, j;
  size_t m = kp->ps->pkpparams->m;
  size_t n = kp->ps->pkpparams->n;
  size_t A_stride = kp->A_stride;
  uint16_t *A = kp->A;

  /* identity portion of the matrix */
  for (i = 0; i < m; ++i) {
    uint32_t welt = w[i];
    st->vecbuf[i] = welt;
  };

  /* non-identity portion */
  for (i = m; i < n; ++i) {
    uint32_t welt = w[i];
    size_t column_offset = (i-m) * A_stride;
    for (j = 0; j < m; ++j) {
      uint32_t aelt = A[column_offset + j];
      st->vecbuf[j] += aelt * welt;
    };
  };

  /* modular reduction */
  for (i = 0; i < m; ++i) {
    out[i] = pkpsig_modulus_modulo(&(kp->ps->pkpparams->q), st->vecbuf[i]);
  };
};

