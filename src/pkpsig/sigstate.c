
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "symmetric.h"
#include "paramset.h"
#include "keys.h"
#include "sigstate.h"
#include "vectenc.h"
#include "sort.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct pkpsig_sigstate *pkpsig_sigstate_new(struct pkpsig_scratch_store *st) {
  const struct pkpsig_paramset *ps = st->ps;
  size_t key_preimage_bytes = ps->seclevel_keypair->preimage_bytes;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t bsgs_bytes = ps->keyfmt->bytes_blindingseedgenseed;
  size_t n = ps->pkpparams->n;
  size_t m = ps->pkpparams->m;
  size_t nruns_short = ps->nruns_short;
  size_t nruns_long = ps->nruns_long;
  size_t nruns = nruns_short + nruns_long;
  size_t i;
  size_t bytes_per_run, ui16s_per_run, extra_byte_runs;
  struct pkpsig_sigstate *sst = calloc(1, sizeof(struct pkpsig_sigstate));

  if (sst == NULL) goto err;

  sst->st = st;

  sst->runs = calloc(nruns, sizeof(struct pkpsig_sigstate_run));
  if (sst->runs == NULL) goto err;

  sst->salt_and_msghash = calloc(key_crhash_bytes * 2, sizeof(uint8_t));
  if (sst->salt_and_msghash == NULL) goto err;

  sst->challenge1_seed = calloc(sig_crhash_bytes * 2, sizeof(uint8_t));
  if (sst->challenge1_seed == NULL) goto err;
  sst->challenge2_seed = sst->challenge1_seed + sig_crhash_bytes;

  sst->unopened_coms = calloc(2 * nruns, sig_crhash_bytes * sizeof(uint8_t));
  if (sst->unopened_coms == NULL) goto err;
  for (i = 0; i < nruns_short; ++i) {
    sst->runs[i].com1 = sst->unopened_coms + (sig_crhash_bytes * i);
    sst->runs[i].com0 = sst->unopened_coms + (sig_crhash_bytes * (nruns + i));
  };
  for (i = nruns_short; i < nruns; ++i) {
    sst->runs[i].com0 = sst->unopened_coms + (sig_crhash_bytes * i);
    sst->runs[i].com1 = sst->unopened_coms + (sig_crhash_bytes * (nruns + i));
  };

  sst->b_vec = calloc(nruns, sizeof(uint8_t));
  if (sst->b_vec == NULL) goto err;

  bytes_per_run = (key_preimage_bytes /* blindingseed */ +
		   n * 4 /* pi_sigma_inv, sigma, z_buf */);
  ui16s_per_run = (n * 3 /* r_sigma, v_pi_sigma, z */ +
		   m /* Ar */);
  extra_byte_runs = (bsgs_bytes*2 + key_preimage_bytes + bytes_per_run-1)/bytes_per_run;

  sst->run_vectors_bytes = calloc(nruns + extra_byte_runs, bytes_per_run * sizeof(uint8_t));
  if (sst->run_vectors_bytes == NULL) goto err;

  sst->run_vectors_ui16s = calloc(nruns, ui16s_per_run * sizeof(uint16_t));
  if (sst->run_vectors_ui16s == NULL) goto err;

  for (i = 0; i < nruns; ++i) {
    struct pkpsig_sigstate_run *run = &(sst->runs[i]);
    uint8_t *p = sst->run_vectors_bytes + (bytes_per_run * i);
    uint16_t *q = sst->run_vectors_ui16s + (ui16s_per_run * i);
    run->blindingseed = p; p += key_preimage_bytes;
    run->pi_sigma_inv = p; p += n;
    run->sigma = p; p += n;
    run->z_buf = p; p += n*2;
    run->r_sigma = q; q += n;
    run->v_pi_sigma = q; q += n;
    run->z = q; q += n;
    run->Ar = q; q += m;
  };

  sst->blindingseedgenseed = sst->run_vectors_bytes + (bytes_per_run * nruns);
  sst->bsg_buf = sst->blindingseedgenseed + bsgs_bytes;

  return sst;

 err:
  pkpsig_sigstate_free(sst);
  return NULL;
};

void pkpsig_sigstate_zero(struct pkpsig_sigstate *sst) {
  const struct pkpsig_paramset *ps = sst->st->ps;
  size_t key_preimage_bytes = ps->seclevel_keypair->preimage_bytes;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t bsgs_bytes = ps->keyfmt->bytes_blindingseedgenseed;
  size_t n = ps->pkpparams->n;
  size_t m = ps->pkpparams->m;
  size_t nruns_short = ps->nruns_short;
  size_t nruns_long = ps->nruns_long;
  size_t nruns = nruns_short + nruns_long;
  size_t i;

  /* Assumes sst was allocated by pkpsig_sigstate_new. */

  assert(sizeof(uint16_t) == 2);
  assert(sizeof(uint8_t) == 1);

  for (i = 0; i < nruns; ++i) {
    struct pkpsig_sigstate_run *run = &(sst->runs[i]);
    memset(run->com0, 0, sig_crhash_bytes);
    memset(run->com1, 0, sig_crhash_bytes);
    memset(run->blindingseed, 0, key_preimage_bytes + n*4);
    memset(run->r_sigma, 0, n*6 + m*2);
  };

  memset(sst->b_vec, 0, nruns);
  memset(sst->blindingseedgenseed, 0, bsgs_bytes*2 + key_preimage_bytes);
  memset(sst->salt_and_msghash, 0, key_crhash_bytes*2);
  memset(sst->challenge1_seed, 0, sig_crhash_bytes * 2);
};

void pkpsig_sigstate_free(struct pkpsig_sigstate *sst) {
  if (sst == NULL) return;

  if (sst->run_vectors_bytes != NULL) free(sst->run_vectors_bytes);
  if (sst->run_vectors_ui16s != NULL) free(sst->run_vectors_ui16s);
  if (sst->unopened_coms != NULL) free(sst->unopened_coms);
  if (sst->b_vec != NULL) free(sst->b_vec);
  if (sst->challenge1_seed != NULL) free(sst->challenge1_seed);
  if (sst->salt_and_msghash != NULL) free(sst->salt_and_msghash);
  if (sst->runs != NULL) free(sst->runs);

  free(sst);
};

void pkpsig_sigstate_set_key_public(struct pkpsig_sigstate *sst, struct pkpsig_keypublic *pub) {
  if (sst->st->ps != pub->kp.ps) abort();
  sst->pub = pub;
};

void pkpsig_sigstate_set_key_secret(struct pkpsig_sigstate *sst, struct pkpsig_keysecret *key) {
  if (sst->st->ps != key->pub.kp.ps) abort();
  sst->pub = &(key->pub);
  sst->key = key;
};

