
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
#include "modulo.h"
#include "permute.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Common functions */

static void compute_z_from_blindingseed(const struct modulus *q_mod, size_t n, struct pkpsig_sigstate_run *run) {
  size_t j;

  /* z = r_sigma + c v_(pi sigma) */

  for (j = 0; j < n; ++j) {
    uint32_t velt = run->v_pi_sigma[j];
    uint32_t c = run->c_and_b & 0x7FFF;
    run->z[j] = pqcr_modulus_modulo(q_mod, (c * velt) + (uint32_t)(run->r_sigma[j]));
  };
};

/* Signer/prover functions */

void pkpsig_zkpshamir_setup(struct pkpsig_sigstate *sst) {
  pkpsig_symmetric_gen_blindingseeds(sst);
};

void pkpsig_zkpshamir_generate_commit1s(struct pkpsig_sigstate *sst) {
  struct pkpsig_scratch_store *st = sst->st;
  struct pkpsig_keysecret *key = sst->key;
  size_t i, nruns;
  uint16_t *r_buf = (uint16_t *)(st->treehash_buf);

  /* _gen_blindingseeds already generated com0; we only need to compute com1. */

  assert(st->ps->pkpparams->m <= st->ps->pkpparams->n);
  pkpsig_permute_prepare(st);

  nruns = key->pub.kp.ps->nruns_short + key->pub.kp.ps->nruns_long;
  for (i = 0; i < nruns; ++i) {
    struct pkpsig_sigstate_run *run = &(sst->runs[i]);
    pkpsig_permute_apply_and_compose_inv(st, run->v_pi_sigma, run->sigma, key->pub.kp.v, key->pi_inv, run->pi_sigma_inv);
    pkpsig_permute_apply_inv(st, r_buf, run->r_sigma, run->sigma);
    pkpsig_mult_vec_by_A(st, &(key->pub.kp), run->Ar, r_buf);
  };

  memset(r_buf, 0, sizeof(uint16_t) * (size_t)(key->pub.kp.ps->pkpparams->n));

  pkpsig_symmetric_gen_com1s(sst, 0);
};

void pkpsig_zkpshamir_generate_commit2s(struct pkpsig_sigstate *sst) {
  struct pkpsig_keysecret *key = sst->key;
  const struct modulus *mod = &(key->pub.kp.ps->pkpparams->q);
  size_t n = key->pub.kp.ps->pkpparams->n;
  size_t i, nruns;

  nruns = key->pub.kp.ps->nruns_short + key->pub.kp.ps->nruns_long;
  for (i = 0; i < nruns; ++i) {
    struct pkpsig_sigstate_run *run = &(sst->runs[i]);
    compute_z_from_blindingseed(mod, n, run);
  };
};

void pkpsig_zkpshamir_encode_proofs(struct pkpsig_sigstate *sst, uint8_t *outbuf) {
  struct pkpsig_scratch_store *st = sst->st;
  struct pkpsig_keysecret *key = sst->key;
  const struct pkpsig_paramset *ps = key->pub.kp.ps;
  size_t key_preimage_bytes = ps->seclevel_keypair->preimage_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t n = key->pub.kp.ps->pkpparams->n;
  size_t i, j;
  size_t nruns_short = ps->nruns_short;
  size_t nruns_long = ps->nruns_long;
  size_t nruns = nruns_short + nruns_long;
  int merge_vect_roots = ps->merge_vect_roots;
  int squish_perms = ps->squish_perms;
  const struct vectcoder *vc_z;
  const struct vectcoder *vc_perm;
  size_t nbytes_common, nbytes_short, nbytes_z, nbytes_perm;
  uint8_t *pcommon;
  uint8_t *pshort;
  uint8_t *plong;
  uint32_t *z_buf = st->vecbuf;
  uint32_t *perm_buf = z_buf + n;
  uint32_t *proots;

  nbytes_common = sig_crhash_bytes; /* com_(1-b) */
  nbytes_short = key_preimage_bytes; /* blindingseed */

  vc_z = ps->pkpparams->vc_sig_z;
  if (squish_perms) {
    vc_perm = ps->pkpparams->vc_sig_perm_squished;
  } else {
    vc_perm = ps->pkpparams->vc_sig_perm_unsquished;
  };

  if (merge_vect_roots) {
    nbytes_z = pqcr_vectcoder_get_nbytes_separate_root(vc_z);
    nbytes_perm = pqcr_vectcoder_get_nbytes_separate_root(vc_perm);
  } else {
    nbytes_z = pqcr_vectcoder_get_nbytes(vc_z);
    nbytes_perm = pqcr_vectcoder_get_nbytes(vc_perm);
  };

  pcommon = outbuf;
  pshort = pcommon + (nbytes_common * nruns);
  plong = pshort + (nbytes_short * nruns_short);

  proots = (uint32_t *)(st->treehash_buf);

  for (i = 0; i < nruns; ++i) {
    struct pkpsig_sigstate_run *run = &(sst->runs[i]);
    int b = (run->c_and_b >> 15);

    assert(run->run_index == i);

    memcpy(pcommon, (b ? run->com0 : run->com1), nbytes_common);
    pcommon += nbytes_common;

    if (b) {
      /* long-proof run */
      if (squish_perms) pkpsig_perm_squish(st, run->sigma);

      for (j = 0; j < n; ++j) {
        z_buf[j] = run->z[j];
        perm_buf[j] = run->sigma[j];
      };

      if (merge_vect_roots) {
        pqcr_vectcoder_encode_separate_root(vc_z, plong, proots, z_buf);
        plong += nbytes_z; ++proots;

        pqcr_vectcoder_encode_separate_root(vc_perm, plong, proots, perm_buf);
        plong += nbytes_perm; ++proots;
      } else {
        pqcr_vectcoder_encode(vc_z, plong, z_buf);
        plong += nbytes_z;

        pqcr_vectcoder_encode(vc_perm, plong, perm_buf);
        plong += nbytes_perm;
      };
    } else {
      /* short-proof run */
      memcpy(pshort, run->blindingseed, nbytes_short);
      pshort += nbytes_short;
    };
  };

  if (merge_vect_roots) {
    pqcr_vectcoder_encode(ps->vc_runvec_heads, plong, (uint32_t *)(st->treehash_buf));
  };
};

/* Verifier functions */

void pkpsig_zkpshamir_decode_proofs(struct pkpsig_sigstate *sst, const uint8_t *inbuf) {
  struct pkpsig_scratch_store *st = sst->st;
  struct pkpsig_keypublic *pub = sst->pub;
  const struct pkpsig_paramset *ps = pub->kp.ps;
  size_t key_preimage_bytes = ps->seclevel_keypair->preimage_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t n = ps->pkpparams->n;
  size_t i, j;
  size_t nruns_short = ps->nruns_short;
  size_t nruns_long = ps->nruns_long;
  size_t nruns = nruns_short + nruns_long;
  int merge_vect_roots = ps->merge_vect_roots;
  int squish_perms = ps->squish_perms;
  const struct vectcoder *vc_z;
  const struct vectcoder *vc_perm;
  size_t nbytes_common, nbytes_short, nbytes_z, nbytes_perm, nbytes_long;
  const uint8_t *pshort;
  const uint8_t *plong;
  uint32_t *z_buf = st->vecbuf;
  uint32_t *perm_buf = z_buf + n;
  uint32_t *proots;

  nbytes_common = sig_crhash_bytes; /* com_(1-b) */
  nbytes_short = key_preimage_bytes; /* blindingseed */

  vc_z = ps->pkpparams->vc_sig_z;
  if (squish_perms) {
    vc_perm = ps->pkpparams->vc_sig_perm_squished;
  } else {
    vc_perm = ps->pkpparams->vc_sig_perm_unsquished;
  };

  if (merge_vect_roots) {
    nbytes_z = pqcr_vectcoder_get_nbytes_separate_root(vc_z);
    nbytes_perm = pqcr_vectcoder_get_nbytes_separate_root(vc_perm);
  } else {
    nbytes_z = pqcr_vectcoder_get_nbytes(vc_z);
    nbytes_perm = pqcr_vectcoder_get_nbytes(vc_perm);
  };
  nbytes_long = nbytes_z + nbytes_perm;

  /* _symmetric_expand_challenge2s has already set the run_index fields. */

  memcpy(sst->unopened_coms, inbuf, (nbytes_common * nruns));
  pshort = inbuf + (nbytes_common * nruns);
  plong = pshort + (nbytes_short * nruns_short);

  proots = (uint32_t *)(st->treehash_buf);
  if (merge_vect_roots) {
    pqcr_vectcoder_decode(ps->vc_runvec_heads,
                          proots,
                          plong + (nbytes_long * nruns_long));
  };

  /* short-proof runs */
  for (i = 0; i < nruns_short; ++i) {
    struct pkpsig_sigstate_run *run = &(sst->runs[i]);
    memcpy(run->blindingseed, pshort, nbytes_short);
    pshort += nbytes_short;
  };

  /* long-proof runs */
  for (i = nruns_short; i < nruns; ++i) {
    struct pkpsig_sigstate_run *run = &(sst->runs[i]);

    if (merge_vect_roots) {
      pqcr_vectcoder_decode_separate_root(vc_z, z_buf, plong, *proots);
      plong += nbytes_z; ++proots;

      pqcr_vectcoder_decode_separate_root(vc_perm, perm_buf, plong, *proots);
      plong += nbytes_perm; ++proots;
    } else {
      pqcr_vectcoder_decode(vc_z, z_buf, plong);
      plong += nbytes_z;

      pqcr_vectcoder_decode(vc_perm, perm_buf, plong);
      plong += nbytes_perm;
    };

    for (j = 0; j < n; ++j) {
      run->z[j] = z_buf[j];
      run->sigma[j] = perm_buf[j];
    };

    if (squish_perms) pkpsig_perm_unsquish(st, run->sigma);
  };
};

void pkpsig_zkpshamir_regenerate_commits(struct pkpsig_sigstate *sst) {
  struct pkpsig_scratch_store *st = sst->st;
  struct pkpsig_keypublic *pub = sst->pub;
  const struct pkpsig_paramset *ps = pub->kp.ps;
  const struct modulus *mod = &(ps->pkpparams->q);
  const uint16_t *v = pub->kp.v;
  uint32_t big_zero = ((uint32_t)(mod->orig)) * ((uint32_t)(mod->orig));
  size_t n = ps->pkpparams->n;
  size_t m = ps->pkpparams->m;
  size_t i, j;
  size_t nruns_short = ps->nruns_short;
  size_t nruns_long = ps->nruns_long;
  size_t nruns = nruns_short + nruns_long;

  pkpsig_permute_prepare(st);

  /* short-proof runs */
  for (i = 0; i < nruns_short; ++i) {
    struct pkpsig_sigstate_run *run = &(sst->runs[i]);

    /* _symmetric_expand_blindingseeds has recomputed (com0,
       pi_sigma_inv, r_sigma); we only need to compute v_pi_sigma and
       z. */

    pkpsig_permute_apply_inv(st, run->v_pi_sigma, v, run->pi_sigma_inv);
    compute_z_from_blindingseed(mod, n, run);
  };

  /* _mult_vec_by_A will clobber the padding which
     pkpsig_permute_prepare puts into vecbuf if m > n.  But note that
     m >= n makes key recovery trivial. */
  assert(st->ps->pkpparams->m <= st->ps->pkpparams->n);

  /* long-proof runs */
  for (i = nruns_short; i < nruns; ++i) {
    struct pkpsig_sigstate_run *run = &(sst->runs[i]);
    uint16_t *z_sigma_inv = run->r_sigma;

    /* We need to compute com1=H(A*r) from sigma and z=(r + c*v_pi)_sigma. */

    pkpsig_permute_apply_inv(st, z_sigma_inv, run->z, run->sigma);
    pkpsig_mult_vec_by_A(st, &(pub->kp), run->Ar, z_sigma_inv); /* A*r + c*u */
    for (j = 0; j < m; ++j) {
      uint32_t c = run->c_and_b & 0x7FFF;
      uint32_t uelt = pub->u[j];
      run->Ar[j] = pqcr_modulus_modulo(mod, (big_zero - c*uelt) + (uint32_t)(run->Ar[j]));
    };
  };
  pkpsig_symmetric_gen_com1s(sst, 1);
};

