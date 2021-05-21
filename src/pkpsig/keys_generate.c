
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
#include "symmetric.h"

#include "keys_internal.h"

#include "randombytes.h"

#include <assert.h>

void pkpsig_key_generate(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key) {
  const struct pkpsig_keyfmt *keyfmt = key->pub.kp.ps->keyfmt;
  int rv;

  assert(st->ps == key->pub.kp.ps);

  /* Generate the most secret part first, as a separate RNG call */
  pkpsig_randombytes(key->skblob + keyfmt->bytes_pubparamseed, keyfmt->bytes_seckeyseed);
  pkpsig_randombytes(key->skblob + keyfmt->bytes_pubparamseed + keyfmt->bytes_seckeyseed,
		     keyfmt->bytes_saltgenseed);

  /* Now generate a parameter seed by rejection sampling */
  rv = -1;
  while (rv != 0) {
    pkpsig_randombytes(key->skblob, keyfmt->bytes_pubparamseed);
    rv = pkpsig_symmetric_expand_v(st, &(key->pub.kp), key->skblob, 1);
  };

  pkpsig_key_unpack_skblob_internal(st, key, 1);
};

