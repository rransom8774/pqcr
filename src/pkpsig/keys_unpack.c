
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
int pkpsig_key_unpack_skblob_internal(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key, int set_checksum) {
  const struct pkpsig_keyfmt *keyfmt = key->pub.kp.ps->keyfmt;
  uint8_t *skblob_checksum = key->skblob + (keyfmt->bytes_pubparamseed +
                                            keyfmt->bytes_seckeyseed +
                                            keyfmt->bytes_saltgenseed);
  size_t m = key->pub.kp.ps->pkpparams->m;
  size_t i;
  union {
    uint8_t checksum[256];
    uint16_t v_pi[128];
  } x;

  /* avoid stack overflow */
  if (st->ps != key->pub.kp.ps) abort();
  if (st->ps->pkpparams->n > 128) abort();
  if (st->ps->keyfmt->bytes_seckeychecksum > 256) abort();

  /* fill in the public key seed */
  memcpy(key->pub.pkblob, key->skblob, keyfmt->bytes_pubparamseed);

  /* unpack public params */
  (void)pkpsig_symmetric_expand_v(st, &(key->pub.kp), key->skblob, 0);
  pkpsig_symmetric_expand_A(st, &(key->pub.kp), key->skblob);

  /* unpack secret key */
  pkpsig_symmetric_expand_pi_inv(st, key, key->skblob);

  /* recover public key from secret key */
  pkpsig_permute_prepare(st);
  pkpsig_permute_apply_inv(st, x.v_pi, key->pub.kp.v, key->pi_inv);
  pkpsig_mult_vec_by_A(st, &(key->pub.kp), key->pub.u, x.v_pi);

  /* fill in the public key vector */
  for (i = 0; i < m; ++i) st->vecbuf[i] = key->pub.u[i];
  pkpsig_vectcoder_encode(key->pub.kp.ps->pkpparams->vc_pubkey_u,
                          key->pub.pkblob + keyfmt->bytes_pubparamseed,
                          st->vecbuf);

  /* try to clear the buffer */
  memset(x.v_pi, 0, 128 * sizeof(uint16_t));
  /* The popular open-source compilers with too many chefs in the
     kitchen will try to "optimize out" attempts to erase memory like
     the memset above.  Aliasing the checksum output buffer, used
     below by a function in another source file, onto the secret
     vector may help. */

  /* regenerate checksum */
  pkpsig_symmetric_seckeychecksum(st, key, x.checksum);

  if (set_checksum) {
    /* write the checksum into key->skblob */
    memcpy(skblob_checksum, x.checksum, keyfmt->bytes_seckeychecksum);
    return 0;
  } else {
    /* check the checksum in key->skblob */
    if (memcmp(skblob_checksum, x.checksum, keyfmt->bytes_seckeychecksum) == 0) {
      return 0;
    } else {
      return -1;
    };
  };
};

int pkpsig_key_unpack_skblob(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key) {
  return pkpsig_key_unpack_skblob_internal(st, key, 0);
};

int pkpsig_key_unpack_pkblob(struct pkpsig_scratch_store *st, struct pkpsig_keypublic *pub) {
  const struct pkpsig_paramset *ps = pub->kp.ps;
  uint8_t *u_bytes = pub->pkblob + pub->kp.ps->keyfmt->bytes_pubparamseed;
  uint32_t *vecbuf = st->vecbuf;
  uint16_t *u = pub->u;
  size_t m = ps->pkpparams->m;
  size_t i;

  /* unpack public params */
  (void)pkpsig_symmetric_expand_v(st, &(pub->kp), pub->pkblob, 0);
  pkpsig_symmetric_expand_A(st, &(pub->kp), pub->pkblob);

  /* decode the public key vector */
  pkpsig_vectcoder_decode(ps->pkpparams->vc_pubkey_u, vecbuf, u_bytes);

  for (i = 0; i < m; ++i) {
    u[i] = vecbuf[i];
  };

  return 0;
};

