#ifndef X5xc2z2nl0lzs41i8pkge8uqiv8zn1irh1kw8jt6ogz7culohlgtuvh72uzgodkvf
#define X5xc2z2nl0lzs41i8pkge8uqiv8zn1irh1kw8jt6ogz7culohlgtuvh72uzgodkvf

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

struct pkpsig_sigstate_run {
  uint8_t *com0; /* opened by short-proof runs */
  uint8_t *com1; /* opened by long-proof runs */
  uint8_t *blindingseed;
  uint16_t *r_sigma;
  uint8_t *pi_sigma_inv;
  uint8_t *sigma;
  uint16_t *v_pi_sigma;
  uint16_t *z;
  uint8_t *z_buf;
  uint16_t *Ar;
  uint16_t run_index;
  uint16_t c_and_b; /* b in high bit; b==1 indicates long proof */
};

struct pkpsig_sigstate {
  struct pkpsig_scratch_store *st;
  struct pkpsig_keypublic *pub;

  uint8_t *salt_and_msghash;
  uint8_t *challenge1_seed;
  uint8_t *challenge2_seed;
  struct pkpsig_sigstate_run *runs;

  /* used for verification only */
  uint8_t *unopened_coms;
  uint8_t *b_vec;

  /* used for signing only */
  struct pkpsig_keysecret *key;
  uint8_t *blindingseedgenseed;
  uint8_t *bsg_buf;

  /* optimization */
  uint8_t *run_vectors_bytes;
  uint16_t *run_vectors_ui16s;
};

struct pkpsig_sigstate *pkpsig_sigstate_new(struct pkpsig_scratch_store *st);
void pkpsig_sigstate_zero(struct pkpsig_sigstate *sst);
void pkpsig_sigstate_free(struct pkpsig_sigstate *sst);

void pkpsig_sigstate_set_key_public(struct pkpsig_sigstate *sst, struct pkpsig_keypublic *pub);
void pkpsig_sigstate_set_key_secret(struct pkpsig_sigstate *sst, struct pkpsig_keysecret *key);

#endif
