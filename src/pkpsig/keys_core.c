
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "keys.h"
#include "paramset.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "keys_internal.h"

static int pkpsig_key_public_init(struct pkpsig_keypublic *pub) {
  struct pkpsig_keyparams *kp = &(pub->kp);
  const struct pkpsig_paramset *ps = kp->ps;
  size_t n = ps->pkpparams->n;
  size_t m = ps->pkpparams->m;
  size_t m_align_mask = (((size_t)1) << PKPSIG_MATRIX_COLUMN_ALIGNMENT_BITS) - 1;
  size_t m_aligned = (((m + m_align_mask) >> PKPSIG_MATRIX_COLUMN_ALIGNMENT_BITS) <<
                      PKPSIG_MATRIX_COLUMN_ALIGNMENT_BITS);

  kp->v = calloc(n, sizeof(uint16_t));
  if (kp->v == NULL) return -1;

  kp->A_stride = m_aligned;
  kp->A = calloc(n * m_aligned, sizeof(uint16_t));
  if (kp->A == NULL) return -1;

  pub->u = calloc(m, sizeof(uint16_t));
  if (pub->u == NULL) return -1;

  pub->pkblob = calloc(pkpsig_paramset_get_pkblob_bytes(ps), sizeof(uint8_t));
  if (pub->pkblob == NULL) return -1;

  return 0;
};

struct pkpsig_keypublic *pkpsig_key_public_new(const struct pkpsig_paramset *ps) {
  struct pkpsig_keypublic *pub = calloc(1, sizeof(struct pkpsig_keypublic));

  if (pub == NULL) goto err;

  pub->kp.ps = ps;

  if (pkpsig_key_public_init(pub) != 0) goto err;

  return pub;

 err:
  pkpsig_key_public_free(pub);
  return NULL;
};

void pkpsig_key_public_zero(struct pkpsig_keypublic *pub) {
  struct pkpsig_keyparams *kp = &(pub->kp);
  const struct pkpsig_paramset *ps = kp->ps;
  size_t n = ps->pkpparams->n;
  size_t m = ps->pkpparams->m;

  assert(sizeof(uint8_t) == 1);

  memset(kp->v, 0, n * sizeof(uint16_t));
  memset(kp->A, 0, n * kp->A_stride * sizeof(uint16_t));
  memset(pub->u, 0, m * sizeof(uint16_t));
  memset(pub->pkblob, 0, pkpsig_paramset_get_pkblob_bytes(ps));
};

void pkpsig_key_public_free(struct pkpsig_keypublic *pub) {
  struct pkpsig_keyparams *kp;

  if (pub == NULL) return;

  kp = &(pub->kp);

  if (pub->pkblob != NULL) free(pub->pkblob);
  if (pub->u != NULL) free(pub->u);
  if (kp->A != NULL) free(kp->A);
  if (kp->v != NULL) free(kp->v);

  free(pub);
};

static int pkpsig_key_secret_init(struct pkpsig_keysecret *key) {
  struct pkpsig_keyparams *kp = &(key->pub.kp);
  const struct pkpsig_paramset *ps = kp->ps;
  size_t n = ps->pkpparams->n;

  if (pkpsig_key_public_init(&(key->pub)) != 0) return -1;

  key->pi_inv = calloc(n, sizeof(uint8_t));
  if (key->pi_inv == NULL) return -1;

  key->skblob = calloc(pkpsig_paramset_get_skblob_bytes(ps), sizeof(uint8_t));
  if (key->skblob == NULL) return -1;

  return 0;
};

struct pkpsig_keysecret *pkpsig_key_secret_new(const struct pkpsig_paramset *ps) {
  struct pkpsig_keysecret *key = calloc(1, sizeof(struct pkpsig_keysecret));

  if (key == NULL) goto err;

  key->pub.kp.ps = ps;

  if (pkpsig_key_secret_init(key) != 0) goto err;

  return key;

 err:
  pkpsig_key_secret_free(key);
  return NULL;
};

void pkpsig_key_secret_zero(struct pkpsig_keysecret *key) {
  const struct pkpsig_paramset *ps = key->pub.kp.ps;
  size_t n = ps->pkpparams->n;

  memset(key->pi_inv, 0, n * sizeof(uint8_t));
  memset(key->skblob, 0, pkpsig_paramset_get_skblob_bytes(ps));

  return pkpsig_key_public_zero(&(key->pub));
};

void pkpsig_key_secret_free(struct pkpsig_keysecret *key) {
  struct pkpsig_keypublic *pub;
  struct pkpsig_keyparams *kp;

  if (key == NULL) return;

  pub = &(key->pub);
  kp = &(pub->kp);

  if (key->skblob != NULL) free(key->skblob);
  if (key->pi_inv != NULL) free(key->pi_inv);

  if (pub->pkblob != NULL) free(pub->pkblob);
  if (pub->u != NULL) free(pub->u);
  if (kp->A != NULL) free(kp->A);
  if (kp->v != NULL) free(kp->v);

  free(key);
};

