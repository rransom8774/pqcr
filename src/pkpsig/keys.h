#ifndef Xgd6agqilyo18er263uxjkgoez4vdqfzovlgxe9s9g4rdgufm7kqn2qbqsos95wua
#define Xgd6agqilyo18er263uxjkgoez4vdqfzovlgxe9s9g4rdgufm7kqn2qbqsos95wua

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

struct pkpsig_scratch_store;

struct pkpsig_keyparams {
  const struct pkpsig_paramset *ps;
  uint16_t *v;
  uint16_t *A;
  size_t A_stride;
};

struct pkpsig_keypublic {
  struct pkpsig_keyparams kp;
  uint16_t *u;
  uint8_t *pkblob;
};

struct pkpsig_keysecret {
  struct pkpsig_keypublic pub;
  uint8_t *pi_inv;
  uint8_t *skblob;
};

void pkpsig_mult_vec_by_A(struct pkpsig_scratch_store *st, struct pkpsig_keyparams *kp, uint16_t *out, const uint16_t *w);

struct pkpsig_keypublic *pkpsig_key_public_new(const struct pkpsig_paramset *ps);
void pkpsig_key_public_zero(struct pkpsig_keypublic *pub);
void pkpsig_key_public_free(struct pkpsig_keypublic *pub);

struct pkpsig_keysecret *pkpsig_key_secret_new(const struct pkpsig_paramset *ps);
void pkpsig_key_secret_zero(struct pkpsig_keysecret *key);
void pkpsig_key_secret_free(struct pkpsig_keysecret *key);

void pkpsig_key_generate(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key);

int pkpsig_key_unpack_skblob(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key);
int pkpsig_key_unpack_pkblob(struct pkpsig_scratch_store *st, struct pkpsig_keypublic *pub);

#endif
