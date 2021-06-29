
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t compute_treehash_degree(struct pkpsig_paramset *ps) {
  /* SHAKE256 processes 200-64 = 136 bytes per permutation.  We want
     to keep the input size around 512 bytes, and without spilling
     over into a fifth SHAKE256 input block.

     Each tree node is hashed to a length collision-resistant at the
     signature's security level.  Each node's input also contains the
     message hash and its salt, which are CR at the keypair's security
     level, and (currently) 12 bytes of oracle separation data. */
  return ((136*4 - 16 - 2*ps->seclevel_keypair->crhash_bytes) /
          ps->seclevel_signature->crhash_bytes);
};

static const struct pkpsig_seclevel seclevels[] =
  { { "b80",     "80-bit",        "80-bit",  80,  10, 20 },
#define SECLEVEL_b80 0
    { "b96",     "96-bit",        "96-bit",  96,  12, 24 },
#define SECLEVEL_b96 1
    { "b112git", "112-bit (Git-level collision strength)",
      "112-bit (for Git)",                   111, 14, 20 },
#define SECLEVEL_b112git 2
    { "b112",    "112-bit",       "112-bit", 112, 14, 28 },
#define SECLEVEL_b112 3
    { "c1",      "Category 1",    "Cat. 1",  128, 16, 32 },
#define SECLEVEL_c1 4
    { "c1a",     "Category 1A",   "Cat. 1A", 160, 20, 32 },
#define SECLEVEL_c1a 5
    { "c2",      "Category 2",    "Cat. 2",  191, 24, 32 },
#define SECLEVEL_c2 6
    { "c3",      "Category 3",    "Cat. 3",  192, 24, 48 },
#define SECLEVEL_c3 7
    { "c4",      "Category 4",    "Cat. 4",  255, 32, 48 },
#define SECLEVEL_c4 8
    { "c5",      "Category 5",    "Cat. 5",  256, 32, 64 },
#define SECLEVEL_c5 9
    /* This may be more conservative than other "Category 6" definitions. */
    { "c6",      "Category 6",    "Cat. 6",  384, 48, 64 },
#define SECLEVEL_c6 10
    { NULL, NULL, NULL, 0, 0, 0 }
  };

/* Fingerprint formats:
 *
 * >>> 256/math.log2(34)
 * 50.31977785160259
 * >>> sum((7,5,7,4,6) + (3,6,4,6,3))
 * 51
 *
 * >>> 384/math.log2(34)
 * 75.47966677740389
 * >>> sum((7,5,7,4,6) + (3,6,4,6,3) + (6,3,5,4,7))
 * 76
 *
 * >>> 512/math.log2(34)
 * 100.63955570320518
 * >>> sum((6,3,5,4,7) + (3,6,4,6,3) + (7,5,7,4,6) + (4,7,3,7,4))
 * 101
 *
 */

static const uint8_t fprint_line_fmts[][6] =
  { { 7,4,7,4,6, 0 },
    { 4,6,4,6,3, 0 },
    { 6,3,5,4,7, 0 },
    { 4,7,3,7,4 ,0 },
  };

static const pkpsig_fprint_line_format fprint_fmts[3][5] =
  { { fprint_line_fmts[0], fprint_line_fmts[1], NULL, NULL, NULL },
    { fprint_line_fmts[0], fprint_line_fmts[1], fprint_line_fmts[2], NULL, NULL },
    { fprint_line_fmts[2], fprint_line_fmts[1], fprint_line_fmts[0], fprint_line_fmts[3], NULL },
  };

#define KEYFMT_B128 0
#define KEYFMT_B192 1
#define KEYFMT_B256 2
#define N_KEYFMTS   3
static const struct pkpsig_keyfmt keyfmts[N_KEYFMTS] =
  { { 17, 32, 32,  8,  64, fprint_fmts[0] },
    { 25, 48, 48, 12,  96, fprint_fmts[1] },
    { 33, 64, 64, 16, 128, fprint_fmts[2] },
  };

struct paramset_data {
  uint16_t n_runs_short;
  uint8_t n_runs_long;
  uint8_t i_sig_seclevel;
};
static const struct paramset_data paramsets_q797n55m25kc1a[] = {
  {127, 73, SECLEVEL_c1a},
  {105, 57, SECLEVEL_c1},
  {99, 47, SECLEVEL_b112},
  {99, 47, SECLEVEL_b112git},
  {83, 41, SECLEVEL_b96},
  {67, 35, SECLEVEL_b80},
  {0, 0, 0}
};
static const struct paramset_data paramsets_q977n61m28kc2[] = {
  {158, 84, SECLEVEL_c2},
  {135, 69, SECLEVEL_c1a},
  {108, 55, SECLEVEL_c1},
  {95, 48, SECLEVEL_b112},
  {95, 48, SECLEVEL_b112git},
  {80, 42, SECLEVEL_b96},
  {72, 33, SECLEVEL_b80},
  {0, 0, 0}
};
static const struct paramset_data paramsets_q1409n87m42kc4[] = {
  {216, 108, SECLEVEL_c4},
  {160, 82, SECLEVEL_c3},
  {178, 76, SECLEVEL_c2},
  {143, 65, SECLEVEL_c1a},
  {115, 52, SECLEVEL_c1},
  {105, 44, SECLEVEL_b112},
  {105, 44, SECLEVEL_b112git},
  {83, 40, SECLEVEL_b96},
  {77, 31, SECLEVEL_b80},
  {0, 0, 0}
};
static const struct paramset_data paramsets_q1789n111m55kc5[] = {
  {232, 102, SECLEVEL_c5},
  {242, 99, SECLEVEL_c4},
  {176, 76, SECLEVEL_c3},
  {199, 70, SECLEVEL_c2},
  {163, 59, SECLEVEL_c1a},
  {136, 46, SECLEVEL_c1},
  {112, 42, SECLEVEL_b112},
  {121, 40, SECLEVEL_b112git},
  {100, 35, SECLEVEL_b96},
  {85, 29, SECLEVEL_b80},
  {0, 0, 0}
};
static const struct paramset_data paramsets_q1789n111m55kc6[] = {
  {314, 164, SECLEVEL_c6},
  {203, 112, SECLEVEL_c5},
  {211, 109, SECLEVEL_c4},
  {158, 82, SECLEVEL_c3},
  {176, 76, SECLEVEL_c2},
  {148, 63, SECLEVEL_c1a},
  {113, 52, SECLEVEL_c1},
  {100, 45, SECLEVEL_b112},
  {100, 45, SECLEVEL_b112git},
  {85, 39, SECLEVEL_b96},
  {72, 32, SECLEVEL_b80},
  {0, 0, 0}
};

struct keyparams_data {
  const char *name;
  uint16_t q;
  uint8_t n, m;
  uint8_t i_key_seclevel, i_keyfmt;
  const struct paramset_data *paramsets;
};
static const struct keyparams_data keyparamsets[] = {
#define DEFINE_KEYPARAMSET(Q, N, M, KSL, KF) \
  {"q" #Q "n" #N "m" #M "k" #KSL, Q, N, M, SECLEVEL_##KSL, KEYFMT_##KF, paramsets_q##Q##n##N##m##M##k##KSL}
  DEFINE_KEYPARAMSET(797,55,25,c1a,B128),
  DEFINE_KEYPARAMSET(977,61,28,c2,B128),
  DEFINE_KEYPARAMSET(1409,87,42,c4,B192),
  DEFINE_KEYPARAMSET(1789,111,55,c5,B256),
  DEFINE_KEYPARAMSET(1789,111,55,c6,B256),
#undef DEFINE_KEYPARAMSET
  {NULL, 0, 0, 0, 0, 0, NULL}
};

static void free_pkp_param_set(struct pkpsig_pkpparams *pps) {
  if (pps == NULL) return;
  if (pps->vc_pubkey_u != NULL) pqcr_vectcoder_free(pps->vc_pubkey_u);
  if (pps->vc_sig_z != NULL) pqcr_vectcoder_free(pps->vc_sig_z);
  if (pps->vc_sig_perm_unsquished != NULL) pqcr_vectcoder_free(pps->vc_sig_perm_unsquished);
  if (pps->vc_sig_perm_squished != NULL) pqcr_vectcoder_free(pps->vc_sig_perm_squished);
  free(pps);
};

static struct pkpsig_pkpparams *alloc_pkp_param_set(uint16_t q, uint8_t n, uint8_t m, int squish) {
  uint64_t b32 = ((uint64_t)1) << 32;
  uint32_t b24 = ((uint32_t)1) << 24;
  struct pkpsig_pkpparams *pps = NULL;
  uint32_t M[128];
  size_t j;

  pps = calloc(1, sizeof(struct pkpsig_pkpparams));
  if (pps == NULL) goto err;

  if ((n == 0) || (n > 128)) goto err; /* protect the stack */

  if (pqcr_modulus_init(&(pps->q), q) != 0) goto err;
  pps->q_uniform_sampler_maxval = b32 - (b32 % (uint64_t)q) - 1;
  pps->q_reduce_2_24 = b24 % (uint32_t)q;

  pps->n = n;
  pps->m = m;
  pps->n_padlen = pkpsig_sort_anyint32_get_pad_length(n);

  pps->vc_pubkey_u = pqcr_vectcoder_new_uniform_bound(q, m);
  if (pps->vc_pubkey_u == NULL) goto err;

  pps->vc_sig_z = pqcr_vectcoder_new_uniform_bound(q, n);
  if (pps->vc_sig_z == NULL) goto err;

  if (!squish) {
    pps->vc_sig_perm_unsquished = pqcr_vectcoder_new_uniform_bound(n, n);
    if (pps->vc_sig_perm_unsquished == NULL) goto err;
  } else {
    for (j = 0; j < n-1; ++j) {
      M[j] = n - j;
    };
    pps->vc_sig_perm_squished = pqcr_vectcoder_new(M, n-1);
    if (pps->vc_sig_perm_squished == NULL) goto err;
  };

  return pps;

 err:
  free_pkp_param_set(pps);
  return NULL;
};

static struct pkpsig_paramset *alloc_paramset_from_data(const struct keyparams_data *kp, const char *symalg, const struct paramset_data *psd, int flag) {
  struct pkpsig_paramset *ps = NULL;
  char name_buf[128];
  size_t name_len;

  ps = calloc(1, sizeof(struct pkpsig_paramset));
  if (ps == NULL) goto err;

  ps->symmetric_algo = pkpsig_symmetric_algo_get(symalg);
  if (ps->symmetric_algo == NULL) goto err;

  ps->keyfmt = &(keyfmts[kp->i_keyfmt]);
  ps->seclevel_keypair = &(seclevels[kp->i_key_seclevel]);
  ps->seclevel_signature = &(seclevels[psd->i_sig_seclevel]);

  if (pkpsig_symmetric_algo_check_seclevel(ps->symmetric_algo, ps->seclevel_keypair->preimage_bytes, ps->seclevel_keypair->crhash_bytes) < 0) {
    goto err;
  };

  name_len = snprintf(name_buf, sizeof(name_buf), "%s-%s-s%s%s%c",
                      kp->name, symalg, ps->seclevel_signature->name,
                      flag ? "-" : "", flag);
  if (name_len > sizeof(name_buf) - 1) goto err;
  ps->name = strdup(name_buf);
  if (ps->name == NULL) goto err;

  ps->nruns_short = psd->n_runs_short;
  ps->nruns_long = psd->n_runs_long;

  ps->treehash_degree = compute_treehash_degree(ps);

  switch (flag) {
  case 0:
    ps->squish_perms = 1;
    ps->merge_vect_roots = 0;
    break;
  case 'u':
    ps->squish_perms = 0;
    ps->merge_vect_roots = 0;
    break;
  case 'm':
    ps->squish_perms = 1;
    ps->merge_vect_roots = 1;
    break;
  default:
    goto err;
  }

  ps->pkpparams = alloc_pkp_param_set(kp->q, kp->n, kp->m, ps->squish_perms);
  if (ps->pkpparams == NULL) goto err;

  if (ps->merge_vect_roots) {
    size_t nrl = ps->nruns_long;
    size_t i;
#define MAX_N_RUNS_LONG 164
    vectelt M[MAX_N_RUNS_LONG*2];
    const struct vectcoder *vc_sig_perm =
      (ps->squish_perms ? ps->pkpparams->vc_sig_perm_squished :
       ps->pkpparams->vc_sig_perm_unsquished);
    uint32_t z_root = pqcr_vectcoder_get_root_bound(ps->pkpparams->vc_sig_z);
    uint32_t perm_root = pqcr_vectcoder_get_root_bound(vc_sig_perm);

    if (nrl > MAX_N_RUNS_LONG) goto err;

    for (i = 0; i < nrl; ++i) {
      M[2*i + 0] = z_root;
      M[2*i + 1] = perm_root;
    };

    ps->vc_runvec_heads = pqcr_vectcoder_new(M, nrl*2);
    if (ps->vc_runvec_heads == NULL) goto err;
  };

  return ps;

 err:
  pkpsig_paramset_free(ps);
  return NULL;
};

struct pkpsig_paramset *pkpsig_paramset_alloc_by_name(const char *name) {
  char name_buf[128];
  char *p;
  const struct keyparams_data *kp;
  const char *symalg;
  const struct paramset_data *psd;
  int has_flag, flag;
  size_t len;

  len = strlen(name);
  if (len > sizeof(name_buf) - 1) return NULL;
  memcpy(name_buf, name, len); name_buf[len] = '\0';

  p = name_buf;

  len = strcspn(p, "-");
  p[len] = '\0';
  for (kp = keyparamsets; kp->name != NULL; ++kp) {
    if (strcmp(p, kp->name) == 0) break;
  };
  if (kp->name == NULL) return NULL;

  p += len+1;

  len = strcspn(p, "-");
  p[len] = '\0';
  symalg = p;

  p += len+1;

  if (*p != 's') return NULL;
  ++p;
  len = strcspn(p, "-");
  has_flag = (p[len] == '-');
  p[len] = '\0';
  for (psd = kp->paramsets; psd->n_runs_short != 0; ++psd) {
    if (strcmp(p, seclevels[psd->i_sig_seclevel].name) == 0) break;
  };
  if (psd->n_runs_short == 0) return NULL;

  if (has_flag) {
    p += len + 1;
    flag = *p;
    if (flag == '\0') return NULL;

    ++p;
    if (*p != '\0') return NULL;
  } else {
    flag = 0;
  };

  return alloc_paramset_from_data(kp, symalg, psd, flag);
};

struct paramset_from_ui_bits_map_entry {
  uint16_t bits;
  uint8_t i_key_seclevel, i_sig_seclevel;
};
static const struct paramset_from_ui_bits_map_entry paramset_from_ui_bits_map[] = {
  {  80, SECLEVEL_c1a, SECLEVEL_b80     },
  {  96, SECLEVEL_c1a, SECLEVEL_b96     },
  { 111, SECLEVEL_c1a, SECLEVEL_b112git },
  { 112, SECLEVEL_c1a, SECLEVEL_b112    },
  { 128, SECLEVEL_c2,  SECLEVEL_c1      },
  { 160, SECLEVEL_c2,  SECLEVEL_c1a     },
  { 191, SECLEVEL_c4,  SECLEVEL_c2      },
  { 192, SECLEVEL_c4,  SECLEVEL_c3      },
  { 255, SECLEVEL_c5,  SECLEVEL_c4      },
  { 256, SECLEVEL_c5,  SECLEVEL_c5      },
  { 384, SECLEVEL_c6,  SECLEVEL_c6      },
};
#define MAX_UI_SECLEVEL_BITS 384

struct pkpsig_paramset *pkpsig_paramset_alloc_by_ui_seclevel_bits(int bits) {
  int i, j;
  struct paramset_from_ui_bits_map_entry entry = {0, 0, 0};
  const struct keyparams_data *kp = NULL;
  const char *symalg = "shake256";
  const struct paramset_data *psd = NULL;

  if ((bits < 0) || (bits > MAX_UI_SECLEVEL_BITS)) {
    return NULL;
  };

  for (i = 0; paramset_from_ui_bits_map[i].bits < bits; ++i) {
    /* do nothing */
  };

  entry = paramset_from_ui_bits_map[i];

  for (i = 0; keyparamsets[i].name != NULL; ++i) {
    if (keyparamsets[i].i_key_seclevel == entry.i_key_seclevel) {
      kp = &(keyparamsets[i]);
      break;
    };
  };
  if (kp == NULL) return NULL;

  for (i = 0; kp->paramsets[i].n_runs_long != 0; ++i) {
    if (kp->paramsets[i].i_sig_seclevel == entry.i_sig_seclevel) {
      psd = &(kp->paramsets[i]);
      break;
    };
  };
  if (psd == NULL) return NULL;

  return alloc_paramset_from_data(kp, symalg, psd, 0);
};

void pkpsig_paramset_free(struct pkpsig_paramset *ps) {
  if (ps == NULL) return;
  if (ps->name != NULL) free(ps->name);
  if (ps->pkpparams != NULL) free_pkp_param_set(ps->pkpparams);
  if (ps->vc_runvec_heads != NULL) pqcr_vectcoder_free(ps->vc_runvec_heads);
  free(ps);
};

struct enum_symalg_cbdata {
  const struct keyparams_data *kp;
  pkpsig_paramset_enumerate_names_cb cb;
  void *caller_ud;
};

static int enum_symalg_cb(void *ud, const char *symalg) {
  char name_buf[128];
  size_t name_len;
  const struct pkpsig_symmetric_algo *algo = pkpsig_symmetric_algo_get(symalg);
  struct enum_symalg_cbdata *cbd = ud;
  const struct keyparams_data *kp = cbd->kp;
  pkpsig_paramset_enumerate_names_cb cb = cbd->cb;
  void *caller_ud = cbd->caller_ud;
  const struct pkpsig_seclevel *ksl = &(seclevels[kp->i_key_seclevel]);
  const struct paramset_data *psd;
  int rv;

  if (pkpsig_symmetric_algo_check_seclevel(algo, ksl->preimage_bytes, ksl->crhash_bytes) < 0) {
    return 0;
  };

  for (psd = kp->paramsets; psd->n_runs_short != 0; ++psd) {
    name_len = snprintf(name_buf, sizeof(name_buf), "%s-%s-s%s",
                        kp->name, symalg,
                        seclevels[psd->i_sig_seclevel].name);
    if (name_len > sizeof(name_buf) - 1) continue;
    rv = cb(caller_ud, name_buf);
    if (rv != 0) return rv;

    name_len = snprintf(name_buf, sizeof(name_buf), "%s-%s-s%s-u",
                        kp->name, symalg,
                        seclevels[psd->i_sig_seclevel].name);
    if (name_len > sizeof(name_buf) - 1) continue;
    rv = cb(caller_ud, name_buf);
    if (rv != 0) return rv;

    name_len = snprintf(name_buf, sizeof(name_buf), "%s-%s-s%s-m",
                        kp->name, symalg,
                        seclevels[psd->i_sig_seclevel].name);
    if (name_len > sizeof(name_buf) - 1) continue;
    rv = cb(caller_ud, name_buf);
    if (rv != 0) return rv;
  };

  return 0;
};

int pkpsig_paramset_enumerate_names(pkpsig_paramset_enumerate_names_cb cb, void *ud) {
  int rv;
  const struct keyparams_data *kp;
  struct enum_symalg_cbdata cbd = {NULL, cb, ud};

  for (kp = keyparamsets; kp->name != NULL; ++kp) {
    cbd.kp = kp;
    rv = pkpsig_symmetric_algo_enumerate_names(enum_symalg_cb, &cbd);
    if (rv != 0) return rv;
  };

  return 0;
};

int pkpsig_paramset_get_ui_seclevel_bits(const struct pkpsig_paramset *ps) {
  return ps->seclevel_signature->ui_bits;
};

static size_t pieces_to_buf(char *buf, size_t size, const char * const *pieces) {
  char *pos = buf;
  size_t len = 0;
  size_t i;

  if (pos == NULL) {
    size = 0;
  };

  for (i = 0; pieces[i] != NULL; ++i) {
    size_t piece_len = strlen(pieces[i]);

    len += piece_len;

    if (piece_len <= size) {
      memcpy(pos, pieces[i], piece_len);
      pos += piece_len;
      size -= piece_len;
    } else {
      pos = NULL;
      size = 0;
    };
  };

  if (size >= 1) {
    /* NUL-terminate output string */
    *pos = 0;
  };

  return len;
};

/* If size is less than the string length + 1, will stop writing at
   some point before the end of buf (not necessarily writing up to the
   end itself). */
size_t pkpsig_paramset_get_short_desc(const struct pkpsig_paramset *ps, char *buf, size_t size) {
  static const char *const comma = ", ";
  const char *pieces[] =
    { "key ", ps->seclevel_keypair->short_ui_name, comma,
      "sig ", ps->seclevel_signature->short_ui_name, comma,
      "hash ", pkpsig_symmetric_algo_ui_name_short(ps->symmetric_algo),
      NULL
    };

  return pieces_to_buf(buf, size, pieces);
};

/* If size is less than the string length + 1, will stop writing at
   some point before the end of buf (not necessarily writing up to the
   end itself). */
size_t pkpsig_paramset_get_description(const struct pkpsig_paramset *ps, char *buf, size_t size) {
  static const char *const sec = " security ";
  static const char *const comma = ", ";
  const char *pieces[] =
    { "key", sec, ps->seclevel_keypair->long_ui_name, comma,
      "signature", sec, ps->seclevel_signature->long_ui_name, comma,
      "with ", pkpsig_symmetric_algo_ui_name_long(ps->symmetric_algo),
      " hashing",
      NULL
    };

  return pieces_to_buf(buf, size, pieces);
};

size_t pkpsig_paramset_get_fingerprint_lines(const struct pkpsig_paramset *ps) {
  const pkpsig_fprint_line_format *fprint_fmt = ps->keyfmt->fingerprint_format;
  size_t i;

  for (i = 0; fprint_fmt[i] != NULL; ++i) {
    /* do nothing */
  };

  return i;
};

size_t pkpsig_paramset_get_fingerprint_chars(const struct pkpsig_paramset *ps) {
  const pkpsig_fprint_line_format *fprint_fmt = ps->keyfmt->fingerprint_format;
  size_t rv = 0;
  size_t i, j;

  for (i = 0; fprint_fmt[i] != NULL; ++i) {
    const uint8_t *line = fprint_fmt[i];
    for (j = 0; line[j] != 0; ++j) {
      rv += line[j];
      ++rv; /* either ' ' or '\n' */
    };
  };

  --rv; /* no trailing \n */

  return rv;
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

