
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "paramset.h"
#include "vectenc.h"
#include "sort.h"
#include "symmetric.h"

#include <stdlib.h>
#include <string.h>

static size_t compute_treehash_degree(struct pkpsig_paramset *ps) {
  /* SHAKE256 processes 200-64 = 136 bytes per permutation.  We want
     to keep the input size around 512 bytes, and without spilling
     over into a fifth SHAKE256 input block.

     Each tree node is hashed to a length collision-resistant at the
     keypair's security level, and each node's input also contains the
     message hash and its salt (also keypair CR) and 12 bytes of
     oracle separation data. */
  return ((136*4 - 16) / ps->seclevel_keypair->crhash_bytes) - 2;
};

static const struct pkpsig_seclevel seclevels[] =
  { { "c1",  16, 32 },
    { "c1a", 20, 32 },
    { "c2",  24, 32 },
    { "c3",  24, 48 },
    { "c4",  32, 48 },
    { "c5",  32, 64 },
    { "c6",  48, 64 }, /* may be more conservative than other definitions */
    { "b112git", 14, 20},
    { "b112",    14, 28},
    { "b96",     12, 24},
    { "b80",     10, 20},
    { NULL, 0, 0 }
  };

enum pkp_param_set_enum {
  PKP_PARAM_SET_q797n55m25,
  PKP_PARAM_SET_q977n61m28,
  PKP_PARAM_SET_q1409n87m42,
  PKP_PARAM_SET_q1789n111m55,
  N_PKP_PARAM_SETS
};
static struct pkpsig_pkpparams pkpparamsets[N_PKP_PARAM_SETS];

#define KEYFMT_B128 0
#define KEYFMT_B192 1
#define KEYFMT_B256 2
#define N_KEYFMTS   3
static const struct pkpsig_keyfmt keyfmts[N_KEYFMTS] =
  { { 17, 32, 32,  8,  64 },
    { 25, 48, 48, 12,  96 },
    { 33, 64, 64, 16, 128 },
  };

enum paramset_enum {
#define DEFINE_PARAMSET(KF,Q,N,M,KSL,SSL,SYM,NRS,NRL)           \
  PARAMSET_q##Q##n##N##m##M##k##KSL##_##SYM##_s##SSL,           \
  PARAMSET_q##Q##n##N##m##M##k##KSL##_##SYM##_s##SSL##_u,       \
  PARAMSET_q##Q##n##N##m##M##k##KSL##_##SYM##_s##SSL##_m,
#include "paramset_list.h"
#undef DEFINE_PARAMSET
  N_PARAMSETS
};
static struct pkpsig_paramset paramsets[N_PARAMSETS];

static void init_pkp_param_set(size_t i, uint16_t q, uint8_t n, uint8_t m) {
  uint64_t b32 = ((uint64_t)1) << 32;
  uint32_t b24 = ((uint32_t)1) << 24;
  struct pkpsig_pkpparams *pps = &(pkpparamsets[i]);
  uint32_t M[128];
  size_t j;

  if ((n == 0) || (n > 128)) abort(); /* protect the stack */

  if (pqcr_modulus_init(&(pps->q), q) != 0) abort();
  pps->q_uniform_sampler_maxval = b32 - (b32 % (uint64_t)q) - 1;
  pps->q_reduce_2_24 = b24 % (uint32_t)q;

  pps->n = n;
  pps->m = m;
  pps->n_padlen = pkpsig_sort_anyint32_get_pad_length(n);

  pps->vc_pubkey_u = pqcr_vectcoder_new_uniform_bound(q, m);
  if (pps->vc_pubkey_u == NULL) abort();

  pps->vc_sig_z = pqcr_vectcoder_new_uniform_bound(q, n);
  if (pps->vc_sig_z == NULL) abort();

  pps->vc_sig_perm_unsquished = pqcr_vectcoder_new_uniform_bound(n, n);
  if (pps->vc_sig_perm_unsquished == NULL) abort();

  for (j = 0; j < n-1; ++j) {
    M[j] = n - j;
  };
  pps->vc_sig_perm_squished = pqcr_vectcoder_new(M, n-1);
  if (pps->vc_sig_perm_squished == NULL) abort();
};

static void init_paramset(const char *name, enum paramset_enum i, int pkp, int keyfmt, int squish, int merge, const char *ksl, const char *ssl, const char *sym, uint16_t nruns_short, uint16_t nruns_long) {
  struct pkpsig_paramset *ps = &(paramsets[i]);
  const struct pkpsig_seclevel *sl;
  int kdone, sdone;

  ps->name = name;
  ps->pkpparams = &(pkpparamsets[pkp]);

  ps->keyfmt = &(keyfmts[keyfmt]);

  sl = &(seclevels[0]); kdone = sdone = 0;
  while ((sl->name != NULL) && ((!kdone) || (!sdone))) {
    if (strcmp(ksl, sl->name) == 0) {
      ps->seclevel_keypair = sl;
      kdone = 1;
    };
    if (strcmp(ssl, sl->name) == 0) {
      ps->seclevel_signature = sl;
      sdone = 1;
    };
    ++sl;
  };

  if ((!kdone) || (!sdone)) abort();

  ps->nruns_short = nruns_short;
  ps->nruns_long = nruns_long;

  /* treehash_degree set at the end */

  ps->squish_perms = squish;
  ps->merge_vect_roots = merge;

  if (merge) {
    uint32_t Mbuf[164*2];
    const struct vectcoder *vc_sig_perm =
      (squish ? ps->pkpparams->vc_sig_perm_squished :
       ps->pkpparams->vc_sig_perm_unsquished);
    uint32_t z_root = pqcr_vectcoder_get_root_bound(ps->pkpparams->vc_sig_z);
    uint32_t perm_root = pqcr_vectcoder_get_root_bound(vc_sig_perm);
    int i;

    if (nruns_long > 164) abort(); /* protect the stack */

    for (i = 0; i < nruns_long; ++i) {
      Mbuf[2*i + 0] = z_root;
      Mbuf[2*i + 1] = perm_root;
    };

    ps->vc_runvec_heads = pqcr_vectcoder_new(Mbuf, nruns_long*2);
  } else {
    ps->vc_runvec_heads = NULL;
  };

  ps->symmetric_algo = pkpsig_symmetric_algo_get(sym);
  if (ps->symmetric_algo == NULL) abort();

  ps->treehash_degree = compute_treehash_degree(ps);
};

#define INIT_STATUS_NOPE 0
#define INIT_STATUS_IN_PROGRESS 1
#define INIT_STATUS_DONE 2
static int init_status = INIT_STATUS_NOPE;

/* Must be called at least once before the first use of _get_by_name.
   In a multithreaded program, the first call must be performed in a
   single thread. */
void pkpsig_paramset_init() {
  switch (init_status) {
  case INIT_STATUS_NOPE:
    break;
  case INIT_STATUS_DONE:
    return;
  case INIT_STATUS_IN_PROGRESS:
    abort(); /* called in multiple threads at once. don't do that. */
  default:
    abort(); /* memory corruption; everything's FUBAR */
  };

  init_status = INIT_STATUS_IN_PROGRESS;

#define INIT_PKP_PARAM_SET(Q,N,M) init_pkp_param_set(PKP_PARAM_SET_q##Q##n##N##m##M, Q, N, M)
  INIT_PKP_PARAM_SET(797,55,25);
  INIT_PKP_PARAM_SET(977,61,28);
  INIT_PKP_PARAM_SET(1409,87,42);
  INIT_PKP_PARAM_SET(1789,111,55);
#undef INIT_PKP_PARAM_SET

#define DEFINE_PARAMSET(KF,Q,N,M,KSL,SSL,SYM,NRS,NRL)                   \
  init_paramset("q" #Q "n" #N "m" #M "k" #KSL "-" #SYM "-s" #SSL,       \
                PARAMSET_q##Q##n##N##m##M##k##KSL##_##SYM##_s##SSL,     \
                PKP_PARAM_SET_q##Q##n##N##m##M,                         \
                KEYFMT_##KF,                                            \
                1,                                                      \
                0,                                                      \
                #KSL,                                                   \
                #SSL,                                                   \
                #SYM,                                                   \
                NRS,                                                    \
                NRL);                                                   \
  init_paramset("q" #Q "n" #N "m" #M "k" #KSL "-" #SYM "-s" #SSL "-u",  \
                PARAMSET_q##Q##n##N##m##M##k##KSL##_##SYM##_s##SSL##_u, \
                PKP_PARAM_SET_q##Q##n##N##m##M,                         \
                KEYFMT_##KF,                                            \
                0,                                                      \
                0,                                                      \
                #KSL,                                                   \
                #SSL,                                                   \
                #SYM,                                                   \
                NRS,                                                    \
                NRL);                                                   \
  init_paramset("q" #Q "n" #N "m" #M "k" #KSL "-" #SYM "-s" #SSL "-m",  \
                PARAMSET_q##Q##n##N##m##M##k##KSL##_##SYM##_s##SSL##_m, \
                PKP_PARAM_SET_q##Q##n##N##m##M,                         \
                KEYFMT_##KF,                                            \
                1,                                                      \
                1,                                                      \
                #KSL,                                                   \
                #SSL,                                                   \
                #SYM,                                                   \
                NRS,                                                    \
                NRL);
#include "paramset_list.h"
#undef DEFINE_PARAMSET

  init_status = INIT_STATUS_DONE;
};

const struct pkpsig_paramset *pkpsig_paramset_get_by_name(const char *name) {
  size_t i;

  if (init_status != INIT_STATUS_DONE) {
    /* FIXME this may leak memory in a multithreaded program */    
    pkpsig_paramset_init();
  };

  for (i = 0; i < N_PARAMSETS; ++i) {
    if (strcmp(name, paramsets[i].name) == 0) return &(paramsets[i]);
  };

  return NULL;
};

int pkpsig_paramset_enumerate(pkpsig_paramset_enumerate_cb cb, void *ud) {
  int rv;
  int i;

  if (init_status != INIT_STATUS_DONE) {
    /* FIXME this may leak memory in a multithreaded program */    
    pkpsig_paramset_init();
  };

  for (i = 0; i < N_PARAMSETS; ++i) {
    rv = cb(ud, &paramsets[i]);
    if (rv != 0) return rv;
  };

  return 0;
};

int pkpsig_paramset_enumerate_names(pkpsig_paramset_enumerate_names_cb cb, void *ud) {
  int rv;
  int i;

  if (init_status != INIT_STATUS_DONE) {
    /* FIXME this may leak memory in a multithreaded program */    
    pkpsig_paramset_init();
  };

  for (i = 0; i < N_PARAMSETS; ++i) {
    rv = cb(ud, paramsets[i].name);
    if (rv != 0) return rv;
  };

  return 0;
};

size_t pkpsig_paramset_get_pkblob_bytes(const struct pkpsig_paramset *ps) {
  size_t rv;

  rv = ps->keyfmt->bytes_pubparamseed;
  rv += pqcr_vectcoder_get_nbytes(ps->pkpparams->vc_pubkey_u);

  return rv;
};

size_t pkpsig_paramset_get_skblob_bytes(const struct pkpsig_paramset *ps) {
  const struct pkpsig_keyfmt *keyfmt = ps->keyfmt;

  return (keyfmt->bytes_pubparamseed +
          keyfmt->bytes_seckeyseed +
          keyfmt->bytes_saltgenseed +
          keyfmt->bytes_seckeychecksum);
};

size_t pkpsig_paramset_get_sig_bytes(const struct pkpsig_paramset *ps) {
  const struct pkpsig_pkpparams *pkpparams = ps->pkpparams;
  size_t key_preimage_bytes = ps->seclevel_keypair->preimage_bytes;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  size_t nruns_short = ps->nruns_short;
  size_t nruns_long = ps->nruns_long;
  size_t bytes_hashes = key_crhash_bytes + (sig_crhash_bytes*2);
  size_t bytes_common = sig_crhash_bytes * (nruns_short + nruns_long);
  size_t bytes_short = key_preimage_bytes * nruns_short;
  size_t (*vc_get_nbytes)(const struct vectcoder *vc) =
    (ps->merge_vect_roots ?
     pqcr_vectcoder_get_nbytes_separate_root :
     pqcr_vectcoder_get_nbytes);
  size_t bytes_z = vc_get_nbytes(pkpparams->vc_sig_z);
  size_t bytes_perm = vc_get_nbytes(ps->squish_perms ?
                                    pkpparams->vc_sig_perm_squished :
                                    pkpparams->vc_sig_perm_unsquished);
  size_t bytes_long = (bytes_z + bytes_perm) * nruns_long;
  size_t bytes_heads = (ps->merge_vect_roots ?
                        pqcr_vectcoder_get_nbytes(ps->vc_runvec_heads) :
                        0);
  return (bytes_hashes + bytes_common + bytes_short + bytes_long + bytes_heads);
};

