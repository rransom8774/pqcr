
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "sign_api_simple.h"

#include "pkpsig/api_unified.h"
#include "pkpsig/paramset.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static ssize_t pkpsig_get_publickey_bytes_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name) {
  return pkpsig_simple_get_publickey_bytes(paramset_name);
};
static ssize_t pkpsig_get_secretkey_bytes_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name) {
  return pkpsig_simple_get_secretkey_bytes(paramset_name);
};
static ssize_t pkpsig_get_signature_bytes_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name) {
  return pkpsig_simple_get_signature_bytes(paramset_name);
};

static int pkpsig_enumerate_paramset_names_fn(const struct pqcr_sign_algo_simple *algo, pqcr_enumerate_names_cb cb, void *ud) {
  pkpsig_paramset_enumerate_names(cb, ud);
};

static char *pkpsig_ui_sl_bits_to_ps_name_fn(const struct pqcr_sign_algo_simple *algo, int bits) {
  return pkpsig_simple_ui_seclevel_bits_to_paramset_name(bits);
};
static int pkpsig_ps_name_to_ui_sl_bits_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name) {
  return pkpsig_simple_paramset_name_to_ui_seclevel_bits(paramset_name);
};
static int pkpsig_ps_name_to_keygen_entropy_bits_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name) {
  return pkpsig_simple_paramset_name_to_keygen_entropy_bits(paramset_name);
};

static const char *pkpsig_get_hash_algo_id_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name) {
  return pkpsig_simple_get_hash_algo_name(paramset_name);
};
static char *pkpsig_get_paramset_description_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name) {
  char *rv = NULL;
  ssize_t len, lencheck;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  if (ps == NULL) return NULL;
  len = pkpsig_paramset_get_description(ps, NULL, 0);
  rv = calloc(len+1, sizeof(char));
  if (rv != NULL) {
    lencheck = pkpsig_paramset_get_description(ps, rv, len);
    assert(lencheck == len);
  };
  pkpsig_paramset_free(ps);
  return rv;
};

static int pkpsig_keypair_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, uint8_t *publickey_out, uint8_t *secretkey_out, pqcr_randombytes_cb randombytes_cb, void *ud) {
  return pkpsig_simple_keypair(paramset_name, publickey_out, secretkey_out, randombytes_cb, ud);
};
static int pkpsig_secretkey_to_publickey_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, uint8_t *publickey_out, const uint8_t *secretkey) {
  return pkpsig_simple_secretkey_to_publickey(paramset_name, publickey_out, secretkey);
};

static ssize_t pkpsig_detached_sign_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, uint8_t *sigout, const uint8_t *msg, size_t msglen, const uint8_t *secretkey) {
  int rv = pkpsig_simple_detached_sign(paramset_name, sigout, msg, msglen, secretkey);
  if (rv < 0) return rv;
  return pkpsig_simple_get_signature_bytes(paramset_name);
};

static int pkpsig_detached_verify_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, const uint8_t *sigin, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *publickey) {
  if (siglen != pkpsig_simple_get_signature_bytes(paramset_name)) return -1;
  return pkpsig_simple_detached_verify(paramset_name, sigin, msg, msglen, publickey);
};

static int generic_supercop_sign_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *secretkey) {
  size_t sig_bytes_max = algo->get_signature_bytes_max(algo, paramset_name);
  ssize_t rv;

  *smlen = sig_bytes_max + mlen;

  rv = algo->detached_sign(algo, paramset_name, sm, m, mlen, secretkey);
  if (rv < 0) return rv;

  if (rv != sig_bytes_max) return -1;

  memcpy(sm + rv, m, mlen);
  return 0;
};

static int generic_supercop_sign_open_fn(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *publickey) {
  size_t sig_bytes = algo->get_signature_bytes_max(algo, paramset_name);
  int rv;

  if (smlen < sig_bytes) return -1;

  *mlen = smlen - sig_bytes;

  rv = algo->detached_verify(algo, paramset_name, sm, sig_bytes, sm + sig_bytes, smlen - sig_bytes, publickey);
  if (rv < 0) return rv;

  memcpy(m, sm + sig_bytes, smlen - sig_bytes);
  return 0;
};

static const struct pqcr_sign_algo_simple algo_pkpsig = {
  "pkpsig",

  pkpsig_get_publickey_bytes_fn,
  pkpsig_get_secretkey_bytes_fn,
  pkpsig_get_signature_bytes_fn,
  pkpsig_get_signature_bytes_fn,

  pkpsig_enumerate_paramset_names_fn,

  pkpsig_ui_sl_bits_to_ps_name_fn,
  pkpsig_ps_name_to_ui_sl_bits_fn,
  pkpsig_ps_name_to_keygen_entropy_bits_fn,

  pkpsig_get_hash_algo_id_fn,
  pkpsig_get_paramset_description_fn,

  pkpsig_keypair_fn,
  pkpsig_secretkey_to_publickey_fn,

  pkpsig_detached_sign_fn,
  pkpsig_detached_verify_fn,

  generic_supercop_sign_fn,
  generic_supercop_sign_open_fn,
};

static const struct pqcr_sign_algo_simple * const algos[] = {
  &algo_pkpsig,
};
#define N_ALGOS (sizeof(algos)/sizeof(algos[0]))

const struct pqcr_sign_algo_simple *pqcr_get_sign_algo_simple(const char *name) {
  size_t i;
  for (i = 0; i < N_ALGOS; ++i) {
    if ((algos[i] != NULL) && (strcmp(algos[i]->algo_name, name) == 0)) {
      return algos[i];
    };
  };
  return NULL;
};

int pqcr_enum_sign_algo_simple_names(pqcr_enumerate_names_cb cb, void *ud) {
  size_t i;
  int rv;
  for (i = 0; i < N_ALGOS; ++i) {
    if (algos[i] != NULL) {
      rv = cb(ud, algos[i]->algo_name);
      if (rv != 0) return rv;
    };
  };
  return 0;
};

