#ifndef Xp28q9fdg9w0z1wnenx2y9tg70ew8lgc8s2331df14vpsplonug9b7mu16jc7dkj1
#define Xp28q9fdg9w0z1wnenx2y9tg70ew8lgc8s2331df14vpsplonug9b7mu16jc7dkj1

/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include <stddef.h>
#include <stdint.h>

#include "modulo.h"

struct pkpsig_seclevel {
  const char *name;
  const char *long_ui_name;
  const char *short_ui_name;
  uint16_t ui_bits;
  uint8_t preimage_bytes;
  uint8_t crhash_bytes;
};

struct pkpsig_pkpparams {
  struct modulus q;
  uint32_t q_uniform_sampler_maxval; /* used in symmetric routines */
  uint16_t q_reduce_2_24; /* 2**24 % q, used in symmetric routines */
  uint8_t n, m; /* m < n; n <= 128 */
  size_t n_padlen;

  struct vectcoder *vc_pubkey_u;
  struct vectcoder *vc_sig_z;
  struct vectcoder *vc_sig_perm_unsquished;
  struct vectcoder *vc_sig_perm_squished;
};

typedef const uint8_t *pkpsig_fprint_line_format;

struct pkpsig_keyfmt {
  size_t bytes_pubparamseed;
  size_t bytes_seckeyseed;
  size_t bytes_saltgenseed;
  size_t bytes_seckeychecksum;

  size_t bytes_blindingseedgenseed;

  const pkpsig_fprint_line_format *fingerprint_format;
};

struct pkpsig_paramset {
  char *name;
  struct pkpsig_pkpparams *pkpparams;

  const struct pkpsig_keyfmt *keyfmt;
  const struct pkpsig_seclevel *seclevel_keypair;
  const struct pkpsig_seclevel *seclevel_signature;

  uint16_t nruns_short, nruns_long; /* nruns_short + nruns_long < 32768 */

  uint8_t treehash_degree;

  uint8_t squish_perms;
  uint8_t merge_vect_roots;

  struct vectcoder *vc_runvec_heads;

  const struct pkpsig_symmetric_algo *symmetric_algo;
};

struct pkpsig_paramset *pkpsig_paramset_alloc_by_name(const char *name);
struct pkpsig_paramset *pkpsig_paramset_alloc_by_ui_seclevel_bits(int bits);
void pkpsig_paramset_free(struct pkpsig_paramset *ps);

typedef int (*pkpsig_paramset_enumerate_names_cb)(void *ud, const char *name);

int pkpsig_paramset_enumerate_names(pkpsig_paramset_enumerate_names_cb cb, void *ud);

int pkpsig_paramset_get_ui_seclevel_bits(const struct pkpsig_paramset *ps);
int pkpsig_paramset_get_keygen_entropy_bits(const struct pkpsig_paramset *ps);
size_t pkpsig_paramset_get_short_desc(const struct pkpsig_paramset *ps, char *buf, size_t size);
size_t pkpsig_paramset_get_description(const struct pkpsig_paramset *ps, char *buf, size_t size);
size_t pkpsig_paramset_get_fingerprint_lines(const struct pkpsig_paramset *ps);
size_t pkpsig_paramset_get_fingerprint_chars(const struct pkpsig_paramset *ps);

size_t pkpsig_paramset_get_pkblob_bytes(const struct pkpsig_paramset *ps);
size_t pkpsig_paramset_get_skblob_bytes(const struct pkpsig_paramset *ps);
size_t pkpsig_paramset_get_sig_bytes(const struct pkpsig_paramset *ps);

#endif
