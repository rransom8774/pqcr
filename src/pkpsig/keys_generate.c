
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

#include <assert.h>

void pkpsig_key_generate(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key, pkpsig_randombytes_cb randombytes_cb, void *ud) {
  const struct pkpsig_keyfmt *keyfmt = key->pub.kp.ps->keyfmt;

  assert(st->ps == key->pub.kp.ps);

  /* Generate the most secret part first, as a separate RNG call */
  randombytes_cb(ud, key->skblob, keyfmt->bytes_seckeyseed);
  randombytes_cb(ud, key->skblob + keyfmt->bytes_seckeyseed,
                     keyfmt->bytes_saltgenseed);

  pkpsig_key_unpack_skblob_internal(st, key);
};

