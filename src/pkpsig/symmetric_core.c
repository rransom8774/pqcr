
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

#include "symmetric_internal.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

const struct pkpsig_symmetric_algo *pkpsig_symmetric_algo_get(const char *name) {
  if (strcmp(name, "shake256") == 0) {
    return pkpsig_symmetric_algo_get_shake256();
  } else if (strcmp(name, "xoesch256") == 0) {
    return pkpsig_symmetric_algo_get_xoesch256();
  } else if (strcmp(name, "xoesch384") == 0) {
    return pkpsig_symmetric_algo_get_xoesch384();
  } else {
    return NULL;
  };
};

int pkpsig_symmetric_algo_enumerate_names(pkpsig_symmetric_algo_enumerate_names_cb cb, void *ud) {
  static const char * const names[] = {
    "shake256", "xoesch256", "xoesch384", NULL
  };
  int rv;
  int i;

  for (i = 0; names[i] != NULL; ++i) {
    if (pkpsig_symmetric_algo_get(names[i]) == NULL) continue;
    rv = cb(ud, names[i]); if (rv != 0) return rv;
  };

  return 0;
};

const char *pkpsig_symmetric_algo_name(const struct pkpsig_symmetric_algo *algo) {
  if (algo == NULL) return NULL;
  return algo->name;
};

size_t pkpsig_symmetric_algo_state_bytes(const struct pkpsig_symmetric_algo *algo) {
  return algo->state_bytes;
};

int pkpsig_symmetric_algo_check_seclevel(const struct pkpsig_symmetric_algo *algo, int preimage_bytes, int crhash_bytes) {
  if (preimage_bytes > algo->max_seclevel_preimage_bytes) return -1;
  if (crhash_bytes > algo->max_seclevel_crhash_bytes) return -1;
  return 0;
};

struct pkpsig_scratch_store *pkpsig_scratch_store_new(const struct pkpsig_symmetric_algo *algo) {
  struct pkpsig_scratch_store *rv = calloc(1, sizeof(struct pkpsig_scratch_store));

  rv->algo = algo;

  return rv;
};

static size_t compute_treehash_buf_len(const struct pkpsig_paramset *ps);

void pkpsig_scratch_store_set_paramset(struct pkpsig_scratch_store *st, const struct pkpsig_paramset *ps) {
  size_t len, tmp;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t n = ps->pkpparams->n;
  size_t m = ps->pkpparams->m;
  size_t nruns = ((size_t)(ps->nruns_short)) + ((size_t)(ps->nruns_long));
  int free_bufs = 0;

  st->ps = ps;

  /* random macro names */
#define clmqoj(N) { tmp = (N); if (len < tmp) len = tmp; }
#define uxjhr(dest) { if (len > dest) {free_bufs = 0;}; dest = len; }

  /* Compute maximum size of outputbuf and store it in output_bytes */

  /* Uses of outputbuf:
     - expand_fqvec: veclen * 4 (veclen is n or m)
     - expand_perm: n * 4
     - pkpsig_signature_verify: sig_crhash_bytes */
  len = st->output_bytes;
  assert(m < n);
  /* clmqoj(m * 4); */
  clmqoj(n * 4);
  clmqoj(sig_crhash_bytes);
  uxjhr(st->output_bytes);

  /* Compute maximum size of tmpbuf and store it in tmpbuf_bytes */

  /* Uses of tmpbuf:
     - shake256_hash_ui16vec: n*2 or m*2 */
  len = st->tmpbuf_bytes;
  assert(m < n);
  /* clmqoj(m * 2); */
  clmqoj(n * 2);
  uxjhr(st->tmpbuf_bytes);

  /* Compute maximum size of vecbuf (in uint32_ts) and store it in vec_elts */

  /* vecbuf is used by many functions for vectors of length n, m, or
     sortpad(n).  zkpshamir.c uses it for two vectors at once, total
     length 2*n. */
  len = st->vec_elts;
  assert(m < n);
  clmqoj(pkpsig_sort_anyint32_get_pad_length(n));
  assert(len >= n);
  clmqoj(2*n);
  uxjhr(st->vec_elts);

  /* Compute maximum size of treehash_buf and store it in treehash_buf_bytes */

  /* treehash_buf is used by the treehash functions below, and as
     scratch space for challenge vectors of length nruns and
     sortpad(nruns), as two copies each, and the roots of the (z,
     perm) vectors for long-proof runs. */
  len = st->treehash_buf_bytes;
  clmqoj(compute_treehash_buf_len(ps));
  clmqoj(4 * (nruns + pkpsig_sort_anyint32_get_pad_length(nruns))); /* _challenge2s */
  assert(len >= 8 * nruns); /* _challenge1s */
  clmqoj(8 * (size_t)(ps->nruns_long)); /* used in zkpshamir.c */
  uxjhr(st->treehash_buf_bytes);

  /* Compute maximum size of treehash_leaves and store it in treehash_leaf_count */

  /* treehash_leaves is used by the treehash functions below. */
  len = st->treehash_leaf_count;
  clmqoj(2 * nruns);
  uxjhr(st->treehash_leaf_count);

  /* If any of the buffer sizes was increased, free the old ones to
     prevent disaster. */
  if (free_bufs) pkpsig_scratch_store_free_bufs(st);

  /* The caller is responsible for ensuring that buffers are allocated
     after a paramset change. */

#undef clmqoj
#undef uxjhr

  /* initialize treehash parameter string here */
  st->treehash_params[0] = ps->treehash_degree;
  st->treehash_params[1] = ps->seclevel_signature->crhash_bytes;
  st->treehash_params[2] = ps->seclevel_signature->crhash_bytes;
  pack_ui16(st->treehash_params + 3, ps->nruns_short);
  pack_ui16(st->treehash_params + 5, ps->nruns_long);
};

int pkpsig_scratch_store_alloc_bufs(struct pkpsig_scratch_store *st) {
  pkpsig_scratch_store_free_bufs(st);

  st->algo_state = calloc(st->algo->state_bytes, sizeof(uint8_t));
  st->algo_state_incremental = calloc(st->algo->state_bytes, sizeof(uint8_t));
  st->algo_state_prefix = calloc(st->algo->state_bytes, sizeof(uint8_t));
  st->outputbuf = calloc(st->output_bytes, sizeof(uint8_t));
  st->tmpbuf = calloc(st->tmpbuf_bytes, sizeof(uint8_t));
  st->vecbuf = calloc(st->vec_elts, sizeof(uint32_t));
  st->treehash_buf = calloc(st->treehash_buf_bytes, sizeof(uint8_t));
  st->treehash_leaves = calloc(st->treehash_leaf_count, sizeof(struct pkpsig_sort_blob));

  if ((st->algo_state == NULL) ||
      (st->algo_state_incremental == NULL) ||
      (st->algo_state_prefix == NULL) ||
      (st->outputbuf == NULL) ||
      (st->tmpbuf == NULL) ||
      (st->vecbuf == NULL) ||
      (st->treehash_buf == NULL) ||
      (st->treehash_leaves == NULL)) {
    return -1;
  };
  return 0;
};

/* random macro name */
#define aerlqxz(buf_field, len_field) memset(st->buf_field, 0, st->len_field)

void pkpsig_scratch_store_zero_algo_state(struct pkpsig_scratch_store *st) {
  aerlqxz(algo_state, algo->state_bytes);
  aerlqxz(algo_state_incremental, algo->state_bytes);
  aerlqxz(algo_state_prefix, algo->state_bytes);
};

void pkpsig_scratch_store_zero_bufs(struct pkpsig_scratch_store *st) {
  pkpsig_scratch_store_zero_algo_state(st);
  aerlqxz(outputbuf, output_bytes);
  aerlqxz(tmpbuf, tmpbuf_bytes);
  aerlqxz(vecbuf, vec_elts*4);
  aerlqxz(treehash_buf, treehash_buf_bytes);
};

#undef aerlqxz

void pkpsig_scratch_store_free_bufs(struct pkpsig_scratch_store *st) {

  /* random macro name */
#define olbhqtn(field)                          \
  if (st->field != NULL) {                      \
    free(st->field);                            \
    st->field = NULL;                           \
  }

  olbhqtn(algo_state);
  olbhqtn(algo_state_incremental);
  olbhqtn(algo_state_prefix);
  olbhqtn(outputbuf);
  olbhqtn(tmpbuf);
  olbhqtn(vecbuf);
  olbhqtn(treehash_buf);
  olbhqtn(treehash_leaves);

#undef olbhqtn
};

void pkpsig_scratch_store_free(struct pkpsig_scratch_store *st) {
  if (st != NULL) {
    pkpsig_scratch_store_free_bufs(st);

    free(st);
  };
};

void pkpsig_scratch_store_set_prefix(struct pkpsig_scratch_store *st) {
  memcpy(st->algo_state_prefix, st->algo_state_incremental, st->algo->state_bytes);
};

void pkpsig_scratch_store_use_prefix(struct pkpsig_scratch_store *st) {
  memcpy(st->algo_state_incremental, st->algo_state_prefix, st->algo->state_bytes);
};

static int expand_fqvec(struct pkpsig_scratch_store *st, const struct pkpsig_paramset *ps, uint16_t *outvec, size_t veclen, int check_uniform) {
  size_t i;
  uint32_t max_uniform, reduce24;

  st->algo->expand(st, st->outputbuf, veclen * 4);

  /* veclen is either m or n; st->vecbuf is sized accordingly */
  unpack_ui32vec(st->vecbuf, st->outputbuf, veclen);

  if (check_uniform) {
    /* check for uniformity */
    max_uniform = ps->pkpparams->q_uniform_sampler_maxval;
    for (i = 0; i < veclen; ++i) {
      if (st->vecbuf[i] > max_uniform) {
        return -1;
      };
    };
  };

  /* reduce and put result in outvec */
  reduce24 = ps->pkpparams->q_reduce_2_24;
  for (i = 0; i < veclen; ++i) {
    uint32_t x = st->vecbuf[i];
    x = (x & 0xFFFFFF) + ((x >> 24) * reduce24);
    x = pqcr_modulus_modulo(&(ps->pkpparams->q), x);
    st->vecbuf[i] = outvec[i] = x;
  };

  return 0;
};

int pkpsig_symmetric_expand_v(struct pkpsig_scratch_store *st, struct pkpsig_keyparams *kp, const uint8_t *seed, int check_distinct) {
  size_t i;
  size_t n = kp->ps->pkpparams->n;
  size_t padlen;

  st->algo->hash_init(st, HASHCTX_PUBPARAMS, seed, kp->ps->keyfmt->bytes_pubparamseed);
  st->algo->hash_index(st, HASHIDX_PUBPARAMS_V);

  (void)expand_fqvec(st, kp->ps, kp->v, n, 0);

  if (check_distinct) {
    /* check for distinct elements */
    /* relies on expand_fqvec leaving v in vecbuf */
    padlen = pkpsig_sort_posint32_pad_sortbuf(st->vecbuf, n);
    pkpsig_sort_posint32(st->vecbuf, padlen);
    for (i = 1; i < n; ++i) {
      if (st->vecbuf[i-1] == st->vecbuf[i]) return -1;
    };
  };
  return 0;
};

void pkpsig_symmetric_expand_A(struct pkpsig_scratch_store *st, struct pkpsig_keyparams *kp, const uint8_t *seed) {
  size_t i;
  size_t m = kp->ps->pkpparams->m;
  size_t n = kp->ps->pkpparams->n;

  st->algo->hash_init(st, HASHCTX_PUBPARAMS, seed, kp->ps->keyfmt->bytes_pubparamseed);
  pkpsig_scratch_store_set_prefix(st);

  for (i = m; i < n; ++i) {
    pkpsig_scratch_store_use_prefix(st);
    st->algo->hash_index(st, i);

    (void)expand_fqvec(st, kp->ps, kp->A + ((i-m) * kp->A_stride), m, 0);
  };
};

static int expand_perm(struct pkpsig_scratch_store *st, const struct pkpsig_paramset *ps, uint8_t *outvec, int check_uniform) {
  size_t i, padlen;
  size_t n = ps->pkpparams->n;

  st->algo->expand(st, st->outputbuf, n * 4);

  /* permutation length is always n; vecbuf is sized accordingly */
  unpack_ui32vec(st->vecbuf, st->outputbuf, n);

  assert(n <= 128);
  assert(((n-1) & PERMSAMPLER_INDEX_MASK) == (n-1));

  /* always fill the bottom 7 bits with the index */
  for (i = 0; i < n; ++i) {
    st->vecbuf[i] = (st->vecbuf[i] & PERMSAMPLER_RANDOM_MASK) | i;
  };

  padlen = pkpsig_sort_uint32_pad_sortbuf(st->vecbuf, n);
  pkpsig_sort_uint32(st->vecbuf, padlen);

  if (check_uniform) {
    /* check for uniformity */
    for (i = 1; i < n; ++i) {
      if (((st->vecbuf[i-1] ^ st->vecbuf[i]) & PERMSAMPLER_RANDOM_MASK) == 0) {
        return -1;
      };
    };
  };

  /* mask and put result in outvec */
  for (i = 0; i < n; ++i) {
    outvec[i] = st->vecbuf[i] & PERMSAMPLER_INDEX_MASK;
  };

  return 0;
};

void pkpsig_symmetric_expand_pi_inv(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key, const uint8_t *seed) {
  const struct pkpsig_paramset *ps = key->pub.kp.ps;
  size_t n = ps->pkpparams->n;
  size_t seedbytes = ps->keyfmt->bytes_pubparamseed + ps->keyfmt->bytes_seckeyseed;

  st->algo->hash_init(st, HASHCTX_SECKEYSEEDEXPAND, seed, seedbytes);
  st->algo->hash_index(st, HASHIDX_SECKEYSEEDEXPAND_PI_INV);

  (void)expand_perm(st, ps, key->pi_inv, 0);

  /* erase secrets */
  pkpsig_scratch_store_zero_algo_state(st);
  memset(st->outputbuf, 0, n*4);
  memset(st->vecbuf, 0, n*4);
};

void pkpsig_symmetric_seckeychecksum(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key, uint8_t *outbuf) {
  const struct pkpsig_paramset *ps = key->pub.kp.ps;
  size_t pkblob_bytes = pkpsig_paramset_get_pkblob_bytes(ps);
  uint8_t params[2] = { ps->seclevel_keypair->preimage_bytes,
                        ps->seclevel_keypair->crhash_bytes };

  st->algo->hash_init(st, HASHCTX_SECKEYCHECKSUM, params, 2);
  st->algo->hash_chunk(st, key->pub.pkblob, pkblob_bytes);

  st->algo->expand(st, outbuf, ps->keyfmt->bytes_seckeychecksum);
};

void pkpsig_symmetric_gen_msghash_salt(struct pkpsig_sigstate *sst, const uint8_t *message, size_t messagelen) {
  const struct pkpsig_paramset *ps = sst->key->pub.kp.ps;
  const struct pkpsig_keyfmt *keyfmt = ps->keyfmt;
  uint8_t ctx = HASHCTX_INTERNAL_GENMSGHASHSALT;
  struct pkpsig_chunk chunks[3] =
    { { &ctx, 1 },
      { message, messagelen },
      { sst->key->skblob + keyfmt->bytes_pubparamseed + keyfmt->bytes_seckeyseed,
        keyfmt->bytes_saltgenseed } };

  sst->st->algo->XOF_chunked_input(sst->st, sst->salt_and_msghash, ps->seclevel_keypair->crhash_bytes, chunks, 3);
};

void pkpsig_symmetric_hash_message(struct pkpsig_sigstate *sst, const uint8_t *message, size_t messagelen) {
  struct pkpsig_scratch_store *st = sst->st;
  const struct pkpsig_paramset *ps = sst->pub->kp.ps;
  uint8_t ctx = HASHCTX_MESSAGEHASH;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t pkblob_bytes = pkpsig_paramset_get_pkblob_bytes(ps);
  struct pkpsig_chunk chunks[4] =
    { { &ctx, 1 },
      { sst->salt_and_msghash, key_crhash_bytes },
      { sst->pub->pkblob, pkblob_bytes },
      { message, messagelen } };

  st->algo->XOF_chunked_input(st, sst->salt_and_msghash + key_crhash_bytes, key_crhash_bytes, chunks, 4);
};

static int expand_blindingseed(struct pkpsig_scratch_store *st, const struct pkpsig_paramset *ps, struct pkpsig_sigstate_run *run, uint8_t *seed, size_t seedlen, size_t commit_bytes, int check_uniform) {
  int rv = 0;

  pkpsig_scratch_store_use_prefix(st);
  st->algo->hash_index(st, (HASHIDX_EXPANDBLINDINGSEED_RUN_INDEX_FACTOR * (uint32_t)(run->run_index)) + HASHIDX_EXPANDBLINDINGSEED_COMMITMENT);
  st->algo->hash_chunk(st, seed, seedlen);
  st->algo->expand(st, run->com0, commit_bytes);

  pkpsig_scratch_store_use_prefix(st);
  st->algo->hash_index(st, (HASHIDX_EXPANDBLINDINGSEED_RUN_INDEX_FACTOR * (uint32_t)(run->run_index)) + HASHIDX_EXPANDBLINDINGSEED_PI_SIGMA_INV);
  st->algo->hash_chunk(st, seed, seedlen);
  rv |= expand_perm(st, ps, run->pi_sigma_inv, check_uniform);

  pkpsig_scratch_store_use_prefix(st);
  st->algo->hash_index(st, (HASHIDX_EXPANDBLINDINGSEED_RUN_INDEX_FACTOR * (uint32_t)(run->run_index)) + HASHIDX_EXPANDBLINDINGSEED_R_SIGMA);
  st->algo->hash_chunk(st, seed, seedlen);
  rv |= expand_fqvec(st, ps, run->r_sigma, ps->pkpparams->n, check_uniform);

  return rv;
};

void pkpsig_symmetric_gen_blindingseeds(struct pkpsig_sigstate *sst) {
  struct pkpsig_scratch_store *st = sst->st;
  const struct pkpsig_paramset *ps = sst->pub->kp.ps;
  size_t pubsecseeds_bytes = ps->keyfmt->bytes_pubparamseed + ps->keyfmt->bytes_seckeyseed;
  size_t key_preimage_bytes = ps->seclevel_keypair->preimage_bytes;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t bsgs_bytes = ps->keyfmt->bytes_blindingseedgenseed;
  uint16_t i, nruns;
  int uniform_rv;
  uint8_t ctx_gbs = HASHCTX_INTERNAL_GENBLINDINGSEED;
  uint8_t index_buf[4];
  struct pkpsig_chunk chunks[3] =
    { { &ctx_gbs, 1 },
      { sst->bsg_buf, bsgs_bytes },
      { index_buf, 4 } };

  st->algo->hash_init(st, HASHCTX_INTERNAL_GENBLINDINGSEEDGENSEED, sst->key->skblob, pubsecseeds_bytes);
  st->algo->hash_chunk(st, sst->salt_and_msghash, key_crhash_bytes * 2);
  st->algo->expand(st, sst->blindingseedgenseed, bsgs_bytes);

  nruns = ps->nruns_short + ps->nruns_long;

  for (i = 0; i < nruns; ++i) {
    struct pkpsig_sigstate_run *run = &(sst->runs[i]);
    run->run_index = i;

    memcpy(sst->bsg_buf, sst->blindingseedgenseed, bsgs_bytes);

    do {
      pack_ui32(index_buf, run->run_index);
      st->algo->XOF_chunked_input(st, sst->bsg_buf, bsgs_bytes + key_preimage_bytes,
                                  chunks, 3);

      st->algo->hash_init(st, HASHCTX_EXPANDBLINDINGSEED, sst->salt_and_msghash, key_crhash_bytes * 2);
      pkpsig_scratch_store_set_prefix(st);
      uniform_rv = expand_blindingseed(st, ps, run, sst->bsg_buf + bsgs_bytes, key_preimage_bytes, sig_crhash_bytes, 1);
    } while (uniform_rv != 0);

    memcpy(run->blindingseed, sst->bsg_buf + bsgs_bytes, key_preimage_bytes);
  };

  /* wipe the most sensitive buffers immediately */
  memset(sst->blindingseedgenseed, 0, bsgs_bytes);
  memset(sst->bsg_buf, 0, bsgs_bytes + key_preimage_bytes);
  pkpsig_scratch_store_zero_algo_state(st);
};

void pkpsig_symmetric_expand_blindingseeds(struct pkpsig_sigstate *sst) {
  struct pkpsig_scratch_store *st = sst->st;
  const struct pkpsig_paramset *ps = sst->pub->kp.ps;
  size_t key_preimage_bytes = ps->seclevel_keypair->preimage_bytes;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  uint16_t i, nruns_short;
  struct pkpsig_sigstate_run *run;

  st->algo->hash_init(st, HASHCTX_EXPANDBLINDINGSEED, sst->salt_and_msghash, key_crhash_bytes * 2);
  pkpsig_scratch_store_set_prefix(st);

  /* This routine is called during verification only, so the runs with
     blinding seeds are at the beginning of the array. */
  nruns_short = ps->nruns_short;
  for (i = 0; i < nruns_short; ++i) {
    run = &(sst->runs[i]);

    (void)expand_blindingseed(st, ps, run, run->blindingseed, key_preimage_bytes, sig_crhash_bytes, 0);
  };

  /* No need to erase the input buffer; these seeds aren't our secrets. */
};

void pkpsig_symmetric_gen_com1s(struct pkpsig_sigstate *sst, int verifying) {
  struct pkpsig_scratch_store *st = sst->st;
  const struct pkpsig_paramset *ps = sst->pub->kp.ps;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t i, nruns;
  size_t n = ps->pkpparams->n;
  size_t m = ps->pkpparams->m;
  struct pkpsig_sigstate_run *run;

  st->algo->hash_init(st, HASHCTX_COMMITMENT, sst->salt_and_msghash, key_crhash_bytes * 2);
  pkpsig_scratch_store_set_prefix(st);

  nruns = ps->nruns_short + ps->nruns_long;
  /* During verification, we only recompute com1 for the runs at the
     end of the array. */
  for (i = (verifying ? ps->nruns_short : 0); i < nruns; ++i) {
    run = &(sst->runs[i]);

    pkpsig_scratch_store_use_prefix(st);

    st->algo->hash_index(st, run->run_index);
    st->algo->hash_chunk(st, run->sigma, n);

    st->algo->hash_ui16vec(st, run->Ar, m);

    st->algo->expand(st, run->com1, sig_crhash_bytes);
  };

  /* During signing, the hash inputs are secret. */
  memset(st->tmpbuf, 0, st->tmpbuf_bytes);
};

static size_t compute_treehash_buf_len_step(const struct pkpsig_paramset *ps, size_t nleaves) {
  /* This function makes no attempt to avoid integer overflow.  Do not
     pass unreasonable parameters to it. */

  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t degree = ps->treehash_degree;
  size_t reduced_nodes = (nleaves / degree) + ((nleaves % degree) != 0);

  return reduced_nodes * sig_crhash_bytes;
};

static size_t compute_treehash_buf_len(const struct pkpsig_paramset *ps) {
  size_t rv, tmp;

  /* each com0 and com1 as two separate leaves per run */
  rv = compute_treehash_buf_len_step(ps, 2*(ps->nruns_short + (size_t)(ps->nruns_long)));

  /* each z as one leaf per run */
  tmp = compute_treehash_buf_len_step(ps, ps->nruns_short + (size_t)(ps->nruns_long));
  if (tmp > rv) rv = tmp;

  return rv;
};

static void tree_hash_prehash(struct pkpsig_scratch_store *st) {
  const struct pkpsig_paramset *ps = st->ps;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t i;
  size_t leaf_bytes = st->treehash_node_bytes;
  size_t node_count = st->treehash_node_count;
  struct pkpsig_sort_blob *leaves = st->treehash_leaves;
  uint8_t index_buf[4];
  struct pkpsig_chunk chunks[5] =
    { { &(st->treehash_context), 1 },
      { st->treehash_prefix, st->treehash_prefix_bytes },
      { st->treehash_params, 7 },
      { index_buf, 4 },
      { NULL, leaf_bytes } };

  if (leaf_bytes >= sig_crhash_bytes) {
    /* There is room to pre-hash leaf nodes in place; no need to write into
       the node buffer yet. */

    for (i = 0; i < node_count; ++i) {
      struct pkpsig_sort_blob *leaf = &(leaves[i]);

      pack_ui32(index_buf, leaf->key);
      chunks[4].buf = leaf->value;

      st->algo->XOF_chunked_input(st, leaf->value, sig_crhash_bytes, chunks, 5);
    };
  } else {
    /* Pre-hashing leaf nodes will make them bigger.  (Why would you
       want to do this?)

       Since this case is useless and not used by any supported or
       reasonable paramset, it wouldn't be tested even if the
       implementation tried to support it.  No point in trying. */
    abort();
  };

  st->treehash_node_bytes = sig_crhash_bytes;
};

static void tree_hash_level(struct pkpsig_scratch_store *st) {
  const struct pkpsig_paramset *ps = st->ps;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  uint8_t *ptr_out = st->treehash_buf;
  uint8_t *ptr_out_end;
  size_t i, idx_in, idx_out;
  uint32_t header_index = st->treehash_next_header_index;
  size_t degree = ps->treehash_degree;
  size_t in_node_bytes = st->treehash_node_bytes;
  size_t node_count_in = st->treehash_node_count;
  struct pkpsig_sort_blob *leaves = st->treehash_leaves;

  /* The caller must initialize st->algo_state_prefix to contain the
     context, prefix string, and parameter string. */

  ptr_out_end = ptr_out + sig_crhash_bytes*( (node_count_in/degree) +
                                             ((node_count_in%degree)!=0) );
  assert(ptr_out_end <= st->treehash_buf + st->treehash_buf_bytes);

  idx_in = 0;
  idx_out = 0;

  while (idx_in < node_count_in) {
    pkpsig_scratch_store_use_prefix(st);
    st->algo->hash_index(st, header_index);

    i = 0;
    while ((i < degree) && (idx_in < node_count_in)) {
      st->algo->hash_chunk(st, leaves[idx_in].value, in_node_bytes);
      ++i; ++idx_in;
    };

    st->algo->expand(st, ptr_out, sig_crhash_bytes);
    leaves[idx_out].key = header_index;
    leaves[idx_out].value = ptr_out;
    ++idx_out;
    ++header_index;
    ptr_out += sig_crhash_bytes;
  };

  assert(ptr_out == ptr_out_end);

  st->treehash_node_bytes = sig_crhash_bytes;
  st->treehash_node_count = idx_out;
  st->treehash_next_header_index = header_index;
};

/* Does a full tree hashing operation, and puts the root hash of the
   tree in outbuf.  Inputs are in st->treehash_leaves. */
static void tree_hash(struct pkpsig_scratch_store *st, uint8_t *outbuf, int prehashed) {
  const struct pkpsig_paramset *ps = st->ps;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;

  /* If the Python implementation/spec version is given one leaf node
     and pre-hashing is not performed, it will return that leaf node
     unmodified.  The output string in this case is likely to differ
     in length from every other use.  Since the class of signature
     schemes which this function is intended for do not perform tree
     hashing on a single leaf, and the single-leaf input case is
     useless, we simply refuse to deal with it. */
  assert(prehashed || (st->treehash_node_count > 1));

  st->treehash_next_header_index = (prehashed ? st->treehash_node_count : 0);

  st->algo->hash_init(st, st->treehash_context,
                      st->treehash_prefix, st->treehash_prefix_bytes);
  st->algo->hash_chunk(st, st->treehash_params, 7);
  pkpsig_scratch_store_set_prefix(st);

  while (st->treehash_node_count > 1) {
    tree_hash_level(st);
  };

  /* now dig the last hash out of the buffer */
  memcpy(outbuf, st->treehash_leaves[0].value, sig_crhash_bytes);
};

/* Inputs are in sst->runs[i]->com0 and ->com1 .
   Clobbers them during verification. */
void pkpsig_symmetric_hash_commit1s(struct pkpsig_sigstate *sst, uint8_t *outbuf, int verifying) {
  struct pkpsig_scratch_store *st = sst->st;
  const struct pkpsig_paramset *ps = sst->pub->kp.ps;
  struct pkpsig_sigstate_run *runs = sst->runs;
  struct pkpsig_sort_blob *leaves = st->treehash_leaves;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t i;
  size_t nruns_short = ps->nruns_short;
  size_t nruns = nruns_short + ps->nruns_long;

  /* During signing, runs[i].run_index == i.

     During verification, we recompute com0 for the short runs and
     com1 for the long runs from their openings.  The other
     commitments are transmitted in run-index order, and stashed in a
     separate buffer. */

  if (verifying) {
    uint8_t *unopened_coms = sst->unopened_coms;
    uint8_t *b_vec = sst->b_vec;

    for (i = 0; i < nruns_short; ++i) {
      leaves[i].key = runs[i].run_index * 2 + 0;
      leaves[i].value = runs[i].com0;
    };
    for (i = nruns_short; i < nruns; ++i) {
      leaves[i].key = runs[i].run_index * 2 + 1;
      leaves[i].value = runs[i].com1;
    };

    pkpsig_merge_runs_blob(leaves, nruns_short, nruns, sig_crhash_bytes);

    i = nruns;
    while (i != 0) {
      --i;

      leaves[2*i + 1].key = leaves[i].key;
      leaves[2*i + 1].value = leaves[i].value;

      leaves[2*i].key = 2*i + (1 - b_vec[i]);
      leaves[2*i].value = unopened_coms + (sig_crhash_bytes * i);
    };

    pkpsig_sort_pairs_blob(leaves, nruns*2, sig_crhash_bytes);
  } else {
    /* signing */
    for (i = 0; i < nruns; ++i) {
      leaves[i*2 + 0].key = runs[i].run_index * 2 + 0;
      leaves[i*2 + 0].value = runs[i].com0;
      leaves[i*2 + 1].key = runs[i].run_index * 2 + 1;
      leaves[i*2 + 1].value = runs[i].com1;
    };
  };

  st->treehash_node_count = nruns*2;
  st->treehash_node_bytes = sig_crhash_bytes;
  st->treehash_context = HASHCTX_CHALLENGE1HASH;
  st->treehash_prefix = sst->salt_and_msghash;
  st->treehash_prefix_bytes = key_crhash_bytes*2;

  tree_hash(st, outbuf, 0);
};

void pkpsig_symmetric_expand_challenge1s(struct pkpsig_sigstate *sst, int verifying) {
  struct pkpsig_scratch_store *st = sst->st;
  const struct pkpsig_paramset *ps = sst->pub->kp.ps;
  struct pkpsig_sigstate_run *runs = sst->runs;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  uint32_t nruns = ps->nruns_short + ps->nruns_long;
  uint8_t *outputbuf = st->treehash_buf;
  uint32_t *vecbuf = (uint32_t *)(st->treehash_buf + nruns*4);
  uint32_t reduce24;
  size_t i, padlen;

  /* There are two differences between this function and expand_fqvec:
     the vector is longer than st->vecbuf should be sized to, and
     during verification, the vector elements need to be stored in
     32-bit words to be permuted to the order of the run objects.
     Together, those two issues are enough to justify code
     duplication. */

  st->algo->hash_init(st, HASHCTX_CHALLENGE1EXPAND,
                      sst->salt_and_msghash, key_crhash_bytes*2);
  st->algo->hash_chunk(st, st->treehash_params, 7);
  st->algo->hash_chunk(st, sst->challenge1_seed, sig_crhash_bytes);

  st->algo->expand(st, outputbuf, nruns*4);
  unpack_ui32vec(vecbuf, outputbuf, nruns);

  /* reduce */
  reduce24 = ps->pkpparams->q_reduce_2_24;
  for (i = 0; i < nruns; ++i) {
    uint32_t x = vecbuf[i];
    x = (x & 0xFFFFFF) + ((x >> 24) * reduce24);
    x = pqcr_modulus_modulo(&(ps->pkpparams->q), x);
    vecbuf[i] = x;
  };

  if (verifying) {
    uint8_t *b_vec = sst->b_vec;

    /* During verification, we need to permute the c values computed
       here to the order determined by _expand_challenge2s below. */
    for (i = 0; i < nruns; ++i) {
      uint32_t x = vecbuf[i];
      x |= ((uint32_t)(b_vec[i])) << 30;
      x |= ((uint32_t)i) << 15;
      vecbuf[i] = x;
    };

    padlen = pkpsig_sort_uint32_pad_sortbuf(vecbuf, nruns);
    pkpsig_sort_uint32(vecbuf, padlen);

    for (i = 0; i < nruns; ++i) {
      runs[i].c_and_b |= vecbuf[i] & 0x3FFF;
    };
  } else {
    /* During signing, runs[i].run_index == i, and we just initialize
       runs[i].c_and_b. */
    for (i = 0; i < nruns; ++i) {
      runs[i].c_and_b = vecbuf[i];
    };
  };
};

/* Inputs are in sst->runs[i]->z . */
void pkpsig_symmetric_hash_commit2s(struct pkpsig_sigstate *sst, uint8_t *outbuf, int verifying) {
  struct pkpsig_scratch_store *st = sst->st;
  const struct pkpsig_paramset *ps = sst->pub->kp.ps;
  struct pkpsig_sigstate_run *runs = sst->runs;
  struct pkpsig_sort_blob *leaves = st->treehash_leaves;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t nruns_short = ps->nruns_short;
  size_t nruns = nruns_short + ps->nruns_long;
  size_t i;

  for (i = 0; i < nruns; ++i) {
    pack_ui16vec(runs[i].z_buf, runs[i].z, ps->pkpparams->n);

    leaves[i].key = runs[i].run_index;
    leaves[i].value = runs[i].z_buf;
  };

  st->treehash_node_count = nruns;
  st->treehash_node_bytes = 2 * (size_t)(ps->pkpparams->n);
  st->treehash_context = HASHCTX_CHALLENGE2HASH;
  st->treehash_prefix = sst->salt_and_msghash;
  st->treehash_prefix_bytes = key_crhash_bytes*2;

  tree_hash_prehash(st);

  if (verifying) {
    pkpsig_merge_runs_blob(leaves, nruns_short, nruns, sig_crhash_bytes);
  };

  tree_hash(st, outbuf, 1);
};

void pkpsig_symmetric_expand_challenge2s(struct pkpsig_sigstate *sst, int verifying) {
  struct pkpsig_scratch_store *st = sst->st;
  const struct pkpsig_paramset *ps = sst->pub->kp.ps;
  struct pkpsig_sigstate_run *runs = sst->runs;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  uint32_t nruns_long = ps->nruns_long;
  uint32_t nruns = ps->nruns_short + nruns_long;
  uint8_t *outputbuf = st->treehash_buf;
  uint32_t *vecbuf = (uint32_t *)(st->treehash_buf + nruns*4);
  size_t padlen, i;

  st->algo->hash_init(st, HASHCTX_CHALLENGE2EXPAND,
                      sst->salt_and_msghash, key_crhash_bytes*2);
  st->algo->hash_chunk(st, st->treehash_params, 7);
  st->algo->hash_chunk(st, sst->challenge1_seed, sig_crhash_bytes);
  st->algo->hash_chunk(st, sst->challenge2_seed, sig_crhash_bytes);

  st->algo->expand(st, outputbuf, nruns*4);
  unpack_ui32vec(vecbuf, outputbuf, nruns);

  for (i = 0; i < nruns_long; ++i) {
    vecbuf[i] |= 1;
  };
  for (i = nruns_long; i < nruns; ++i) {
    vecbuf[i] &= 0xFFFFFFFE;
  };

  padlen = pkpsig_sort_uint32_pad_sortbuf(vecbuf, nruns);
  pkpsig_sort_uint32(vecbuf, padlen);

  if (verifying) {
    uint8_t *b_vec = sst->b_vec;

    /* During verification, we need to save the b values in b_vec,
       then sort the run indexes to have short (b==0) runs first and
       set the b bits and the run_index fields of the run objects. */

    for (i = 0; i < nruns; ++i) {
      uint32_t x = vecbuf[i] & 1;
      b_vec[i] = x;
      x = (x << 16) | i;
      vecbuf[i] = x;
    };

    padlen = pkpsig_sort_posint32_pad_sortbuf(vecbuf, nruns);
    pkpsig_sort_posint32(vecbuf, padlen);

    for (i = 0; i < nruns; ++i) {
      uint32_t x = vecbuf[i];
      struct pkpsig_sigstate_run *run = &(runs[i]);
      run->run_index = x & 0xFFFF;
      run->c_and_b = (x >> 1) & 0x8000; /* c isn't set yet */
    };
  } else {
    /* During signing, runs[i].run_index == i, and we just set the b
       bit of runs[i].c_and_b. */
    for (i = 0; i < nruns; ++i) {
      uint32_t x = vecbuf[i] & 1;
      runs[i].c_and_b |= x << 15;
    };
  };
};

