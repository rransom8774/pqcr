
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "keys.h"
#include "paramset.h"
#include "permute.h"
#include "symmetric.h"
#include "vectenc.h"

#include "keys_internal.h"

#include <stdlib.h>
#include <string.h>

/* used by both keygen and signing */
int pkpsig_key_unpack_skblob_internal(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key) {
  const struct pkpsig_keyfmt *keyfmt = key->pub.kp.ps->keyfmt;
  size_t n = key->pub.kp.ps->pkpparams->n;
  size_t m = key->pub.kp.ps->pkpparams->m;
  size_t i;
  uint16_t *v_pi = (uint16_t *)(st->tmpbuf);

  /* avoid stack overflow */
  if (st->ps != key->pub.kp.ps) abort();
  if (st->ps->pkpparams->n > 128) abort();

  /* fill in the public key seed */
  pkpsig_symmetric_expand_pubparamseed_from_seckeyseed(st, key, key->skblob);

  /* unpack public params */
  for (i = 0; i < n; ++i) key->pub.kp.v[i] = pqcr_modulus_modulo(&(key->pub.kp.ps->pkpparams->q), i);
  pkpsig_symmetric_expand_A(st, &(key->pub.kp), key->pub.pkblob);

  /* unpack secret key */
  pkpsig_symmetric_expand_pi_inv(st, key, key->skblob);

  /* recover public key from secret key */
  pkpsig_permute_prepare(st);
  pkpsig_permute_apply_inv(st, v_pi, key->pub.kp.v, key->pi_inv);
  pkpsig_mult_vec_by_A(st, &(key->pub.kp), key->pub.u, v_pi);

  /* fill in the public key vector */
  for (i = 0; i < m; ++i) st->vecbuf[i] = key->pub.u[i];
  pqcr_vectcoder_encode(key->pub.kp.ps->pkpparams->vc_pubkey_u,
                        key->pub.pkblob + keyfmt->bytes_pubparamseed,
                        st->vecbuf);

  /* try to clear the buffer */
  memset(v_pi, 0, n * sizeof(uint16_t));

  return 0;
};

int pkpsig_key_unpack_skblob(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key) {
  return pkpsig_key_unpack_skblob_internal(st, key);
};

int pkpsig_key_unpack_pkblob(struct pkpsig_scratch_store *st, struct pkpsig_keypublic *pub) {
  const struct pkpsig_paramset *ps = pub->kp.ps;
  uint8_t *u_bytes = pub->pkblob + pub->kp.ps->keyfmt->bytes_pubparamseed;
  uint32_t *vecbuf = st->vecbuf;
  uint16_t *u = pub->u;
  size_t n = ps->pkpparams->n;
  size_t m = ps->pkpparams->m;
  size_t i;

  /* unpack public params */
  for (i = 0; i < n; ++i) pub->kp.v[i] = pqcr_modulus_modulo(&(pub->kp.ps->pkpparams->q), i);
  pkpsig_symmetric_expand_A(st, &(pub->kp), pub->pkblob);

  /* decode the public key vector */
  pqcr_vectcoder_decode(ps->pkpparams->vc_pubkey_u, vecbuf, u_bytes);

  for (i = 0; i < m; ++i) {
    u[i] = vecbuf[i];
  };

  return 0;
};

