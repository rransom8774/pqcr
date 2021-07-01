
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "api_unified.h"

#include "paramset.h"
#include "symmetric.h"
#include "keys.h"
#include "sigstate.h"
#include "signatures.h"

#include <stdlib.h>
#include <string.h>

ssize_t pkpsig_simple_get_publickey_bytes(const char *paramset_name) {
  ssize_t rv;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  if (ps == NULL) return -2;
  rv = pkpsig_paramset_get_pkblob_bytes(ps);
  pkpsig_paramset_free(ps);
  return rv;
};

ssize_t pkpsig_simple_get_secretkey_bytes(const char *paramset_name) {
  ssize_t rv;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  if (ps == NULL) return -2;
  rv = pkpsig_paramset_get_skblob_bytes(ps);
  pkpsig_paramset_free(ps);
  return rv;
};

ssize_t pkpsig_simple_get_signature_bytes(const char *paramset_name) {
  ssize_t rv;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  if (ps == NULL) return -2;
  rv = pkpsig_paramset_get_sig_bytes(ps);
  pkpsig_paramset_free(ps);
  return rv;
};

char *pkpsig_simple_ui_seclevel_bits_to_paramset_name(int bits) {
  char *rv = NULL;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_ui_seclevel_bits(bits);
  if (ps == NULL) return NULL;
  rv = ps->name; ps->name = NULL;
  pkpsig_paramset_free(ps);
  return rv;
};

int pkpsig_simple_paramset_name_to_ui_seclevel_bits(const char *paramset_name) {
  ssize_t rv;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  if (ps == NULL) return -2;
  rv = pkpsig_paramset_get_ui_seclevel_bits(ps);
  pkpsig_paramset_free(ps);
  return rv;
};

int pkpsig_simple_paramset_name_to_keygen_entropy_bits(const char *paramset_name) {
  ssize_t rv;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  if (ps == NULL) return -2;
  rv = pkpsig_paramset_get_keygen_entropy_bits(ps);
  pkpsig_paramset_free(ps);
  return rv;
};

const char *pkpsig_simple_get_hash_algo_name(const char *paramset_name) {
  const char *rv;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  if (ps == NULL) return NULL;
  rv = pkpsig_symmetric_algo_name(ps->symmetric_algo);
  pkpsig_paramset_free(ps);
  return rv;
};

const char *pkpsig_simple_get_hash_algo_ui_name_short(const char *paramset_name) {
  const char *rv;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  if (ps == NULL) return NULL;
  rv = pkpsig_symmetric_algo_ui_name_short(ps->symmetric_algo);
  pkpsig_paramset_free(ps);
  return rv;
};

const char *pkpsig_simple_get_hash_algo_ui_name_long(const char *paramset_name) {
  const char *rv;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  if (ps == NULL) return NULL;
  rv = pkpsig_symmetric_algo_ui_name_long(ps->symmetric_algo);
  pkpsig_paramset_free(ps);
  return rv;
};

ssize_t pkpsig_simple_get_paramset_description(const char *paramset_name, char *buf, size_t size) {
  ssize_t rv;
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  if (ps == NULL) return -2;
  rv = pkpsig_paramset_get_description(ps, buf, size);
  pkpsig_paramset_free(ps);
  return rv;
};

int pkpsig_simple_keypair(const char *paramset_name, uint8_t *publickey_out, uint8_t *secretkey_out) {
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  struct pkpsig_scratch_store *st = NULL;
  struct pkpsig_keysecret *key = NULL;
  size_t pkblob_bytes;
  size_t skblob_bytes;
  int rv = 0;

  if (ps == NULL) {
    rv = -2;
    goto end;
  };

  pkblob_bytes = pkpsig_paramset_get_pkblob_bytes(ps);
  skblob_bytes = pkpsig_paramset_get_skblob_bytes(ps);

  st = pkpsig_scratch_store_new(ps->symmetric_algo);
  if (st == NULL) {
    rv = -3;
    goto end;
  };

  pkpsig_scratch_store_set_paramset(st, ps);
  if (pkpsig_scratch_store_alloc_bufs(st) != 0) {
    rv = -3;
    goto end;
  };

  key = pkpsig_key_secret_new(ps);

  if (key == NULL) {
    rv = -3;
    goto end;
  };

  pkpsig_key_generate(st, key);

  memcpy(publickey_out, key->pub.pkblob, pkblob_bytes);
  memcpy(secretkey_out, key->skblob, skblob_bytes);

  pkpsig_key_secret_zero(key);
  pkpsig_scratch_store_zero_bufs(st);

 end:
  pkpsig_key_secret_free(key);
  pkpsig_scratch_store_free(st);
  pkpsig_paramset_free(ps);
  return rv;
};

int pkpsig_simple_secretkey_to_publickey(const char *paramset_name, uint8_t *publickey_out, const uint8_t *secretkey) {
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  struct pkpsig_scratch_store *st = NULL;
  struct pkpsig_keysecret *key = NULL;
  size_t pkblob_bytes;
  size_t skblob_bytes;
  int rv = 0;

  if (ps == NULL) {
    rv = -2;
    goto end;
  };

  pkblob_bytes = pkpsig_paramset_get_pkblob_bytes(ps);
  skblob_bytes = pkpsig_paramset_get_skblob_bytes(ps);

  st = pkpsig_scratch_store_new(ps->symmetric_algo);
  if (st == NULL) {
    rv = -3;
    goto end;
  };

  pkpsig_scratch_store_set_paramset(st, ps);
  if (pkpsig_scratch_store_alloc_bufs(st) != 0) {
    rv = -3;
    goto end;
  };

  key = pkpsig_key_secret_new(ps);

  if (key == NULL) {
    rv = -3;
    goto end;
  };

  memcpy(key->skblob, secretkey, skblob_bytes);
  if (pkpsig_key_unpack_skblob(st, key) < 0) {
    rv = -1;
    goto end;
  };

  memcpy(publickey_out, key->pub.pkblob, pkblob_bytes);

  pkpsig_key_secret_zero(key);
  pkpsig_scratch_store_zero_bufs(st);

 end:
  pkpsig_key_secret_free(key);
  pkpsig_scratch_store_free(st);
  pkpsig_paramset_free(ps);
  return rv;
};

int pkpsig_simple_detached_sign(const char *paramset_name, uint8_t *sigout, const uint8_t *msg, size_t msglen, const uint8_t *secretkey) {
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  struct pkpsig_scratch_store *st = NULL;
  struct pkpsig_keysecret *key = NULL;
  struct pkpsig_sigstate *sst = NULL;
  size_t skblob_bytes;
  int rv = 0;

  if (ps == NULL) {
    rv = -2;
    goto end;
  };

  skblob_bytes = pkpsig_paramset_get_skblob_bytes(ps);

  st = pkpsig_scratch_store_new(ps->symmetric_algo);
  if (st == NULL) {
    rv = -3;
    goto end;
  };

  pkpsig_scratch_store_set_paramset(st, ps);
  if (pkpsig_scratch_store_alloc_bufs(st) != 0) {
    rv = -3;
    goto end;
  };

  key = pkpsig_key_secret_new(ps);
  sst = pkpsig_sigstate_new(st);

  if ((key == NULL) || (sst == NULL)) {
    rv = -3;
    goto end;
  };

  memcpy(key->skblob, secretkey, skblob_bytes);
  if (pkpsig_key_unpack_skblob(st, key) < 0) {
    rv = -1;
    goto end;
  };

  pkpsig_sigstate_set_key_secret(sst, key);

  pkpsig_signature_generate(sst, sigout, msg, msglen);

 end:
  if (sst != NULL) pkpsig_sigstate_zero(sst);
  if (key != NULL) pkpsig_key_secret_zero(key);
  if (st != NULL) pkpsig_scratch_store_zero_bufs(st);

  pkpsig_sigstate_free(sst);
  pkpsig_key_secret_free(key);
  pkpsig_scratch_store_free(st);
  pkpsig_paramset_free(ps);
  return rv;
};

int pkpsig_simple_detached_verify(const char *paramset_name, const uint8_t *sigin, const uint8_t *msg, size_t msglen, const uint8_t *publickey) {
  struct pkpsig_paramset *ps = pkpsig_paramset_alloc_by_name(paramset_name);
  struct pkpsig_scratch_store *st = NULL;
  struct pkpsig_keypublic *pub = NULL;
  struct pkpsig_sigstate *sst = NULL;
  size_t pkblob_bytes;
  int rv = 0;

  if (ps == NULL) {
    rv = -2;
    goto end;
  };

  pkblob_bytes = pkpsig_paramset_get_pkblob_bytes(ps);

  st = pkpsig_scratch_store_new(ps->symmetric_algo);
  if (st == NULL) {
    rv = -3;
    goto end;
  };

  pkpsig_scratch_store_set_paramset(st, ps);
  if (pkpsig_scratch_store_alloc_bufs(st) != 0) {
    rv = -3;
    goto end;
  };

  pub = pkpsig_key_public_new(ps);
  sst = pkpsig_sigstate_new(st);

  if ((pub == NULL) || (sst == NULL)) {
    rv = -3;
    goto end;
  };

  memcpy(pub->pkblob, publickey, pkblob_bytes);
  if (pkpsig_key_unpack_pkblob(st, pub) < 0) {
    rv = -1;
    goto end;
  };

  pkpsig_sigstate_set_key_public(sst, pub);

  rv = pkpsig_signature_verify(sst, sigin, msg, msglen);

 end:
  if (sst != NULL) pkpsig_sigstate_zero(sst);
  if (pub != NULL) pkpsig_key_public_zero(pub);
  if (st != NULL) pkpsig_scratch_store_zero_bufs(st);

  pkpsig_sigstate_free(sst);
  pkpsig_key_public_free(pub);
  pkpsig_scratch_store_free(st);
  pkpsig_paramset_free(ps);
  return rv;
};

int pkpsig_simple_supercop_sign(const char *paramset_name, uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *secretkey) {
  size_t sig_bytes = pkpsig_simple_get_signature_bytes(paramset_name);
  int rv;

  *smlen = sig_bytes + mlen;

  rv = pkpsig_simple_detached_sign(paramset_name, sm, m, mlen, secretkey);
  if (rv != 0) return rv;

  memcpy(sm + sig_bytes, m, mlen);
  return 0;
};

int pkpsig_simple_supercop_sign_open(const char *paramset_name, uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *publickey) {
  size_t sig_bytes = pkpsig_simple_get_signature_bytes(paramset_name);
  int rv;

  if (smlen < sig_bytes) return -1;

  *mlen = smlen - sig_bytes;

  rv = pkpsig_simple_detached_verify(paramset_name, sm, sm + sig_bytes, smlen - sig_bytes, publickey);
  if (rv != 0) return rv;

  memcpy(m, sm + sig_bytes, smlen - sig_bytes);
  return 0;
};

