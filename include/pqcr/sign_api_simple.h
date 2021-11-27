#ifndef X3o9qv0285kd8h1239g1w6tp6pj92yspq35ivf5tuph1o7hszg68mg8i0i769ryi2
#define X3o9qv0285kd8h1239g1w6tp6pj92yspq35ivf5tuph1o7hszg68mg8i0i769ryi2

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

#include <sys/types.h>

typedef int (*pqcr_enumerate_names_cb)(void *ud, const char *name);
typedef int (*pqcr_randombytes_cb)(void *ud, uint8_t *out, size_t bytes);

#define PQCR_SIGN_ALGO_PARSES_PARAMSET_NAMES (((uint32_t)1) << 0)

struct pqcr_sign_algo_simple {
  const char *algo_name;

  uint32_t flags;

  ssize_t (*get_publickey_bytes)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name);
  ssize_t (*get_secretkey_bytes)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name);
  ssize_t (*get_signature_bytes_min)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name);
  ssize_t (*get_signature_bytes_max)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name);

  int (*enumerate_paramset_names)(const struct pqcr_sign_algo_simple *algo, pqcr_enumerate_names_cb cb, void *ud);

  char *(*canonicalize_paramset_name)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name);

  char *(*ui_seclevel_bits_to_paramset_name)(const struct pqcr_sign_algo_simple *algo, int bits);
  int (*paramset_name_to_ui_seclevel_bits)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name);
  int (*paramset_name_to_keygen_entropy_bits)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name);

  const char *(*get_hash_algo_id)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name);
  char *(*get_paramset_description)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name);

  int (*keypair)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, uint8_t *publickey_out, uint8_t *secretkey_out, pqcr_randombytes_cb randombytes_cb, void *ud);
  int (*secretkey_to_publickey)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, uint8_t *publickey_out, const uint8_t *secretkey);

  ssize_t (*detached_sign)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, uint8_t *sigout, const uint8_t *msg, size_t msglen, const uint8_t *secretkey);
  int (*detached_verify)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, const uint8_t *sigin, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *publickey);

  int (*supercop_sign)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *secretkey);
  int (*supercop_sign_open)(const struct pqcr_sign_algo_simple *algo, const char *paramset_name, uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *publickey);
};

const struct pqcr_sign_algo_simple *pqcr_get_sign_algo_simple(const char *name);
int pqcr_enum_sign_algo_simple_names(pqcr_enumerate_names_cb cb, void *ud);

#endif
