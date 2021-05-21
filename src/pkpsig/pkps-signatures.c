
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "symmetric.h"
#include "paramset.h"
#include "keys.h"
#include "sigstate.h"
#include "vectenc.h"
#include "sort.h"
#include "zkpshamir.h"
#include "signatures.h"

#include <string.h>

void pkpsig_signature_generate(struct pkpsig_sigstate *sst, uint8_t *sig, const uint8_t *msg, size_t msglen) {
  const struct pkpsig_paramset *ps = sst->pub->kp.ps;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  uint8_t *p = sig;

  pkpsig_symmetric_gen_msghash_salt(sst, msg, msglen);
  pkpsig_symmetric_hash_message(sst, msg, msglen);
  pkpsig_symmetric_gen_blindingseeds(sst);
  pkpsig_zkpshamir_setup(sst);
  pkpsig_zkpshamir_generate_commit1s(sst);
  pkpsig_symmetric_hash_commit1s(sst, sst->challenge1_seed, 0);
  pkpsig_symmetric_expand_challenge1s(sst, 0);
  pkpsig_zkpshamir_generate_commit2s(sst);
  pkpsig_symmetric_hash_commit2s(sst, sst->challenge2_seed, 0);
  pkpsig_symmetric_expand_challenge2s(sst, 0);

  memcpy(p, sst->salt_and_msghash, key_crhash_bytes); p += key_crhash_bytes;
  memcpy(p, sst->challenge1_seed, sig_crhash_bytes); p += sig_crhash_bytes;
  memcpy(p, sst->challenge2_seed, sig_crhash_bytes); p += sig_crhash_bytes;

  pkpsig_zkpshamir_encode_proofs(sst, p);

  pkpsig_sigstate_zero(sst);
};

int pkpsig_signature_verify(struct pkpsig_sigstate *sst, const uint8_t *sig, const uint8_t *msg, size_t msglen) {
  struct pkpsig_scratch_store *st = sst->st;
  const struct pkpsig_paramset *ps = sst->pub->kp.ps;
  size_t key_crhash_bytes = ps->seclevel_keypair->crhash_bytes;
  size_t sig_crhash_bytes = ps->seclevel_signature->crhash_bytes;
  const uint8_t *p = sig;

  memcpy(sst->salt_and_msghash, p, key_crhash_bytes); p += key_crhash_bytes;
  memcpy(sst->challenge1_seed, p, sig_crhash_bytes); p += sig_crhash_bytes;
  memcpy(sst->challenge2_seed, p, sig_crhash_bytes); p += sig_crhash_bytes;

  pkpsig_symmetric_hash_message(sst, msg, msglen);
  pkpsig_symmetric_expand_challenge2s(sst, 1);
  pkpsig_symmetric_expand_challenge1s(sst, 1);

  pkpsig_zkpshamir_decode_proofs(sst, p);
  pkpsig_symmetric_expand_blindingseeds(sst);
  pkpsig_zkpshamir_regenerate_commits(sst);

  pkpsig_symmetric_hash_commit1s(sst, st->outputbuf, 1);
  if (memcmp(st->outputbuf, sst->challenge1_seed, sig_crhash_bytes) != 0) {
    return -1;
  };

  pkpsig_symmetric_hash_commit2s(sst, st->outputbuf, 1);
  if (memcmp(st->outputbuf, sst->challenge2_seed, sig_crhash_bytes) != 0) {
    return -1;
  };

  return 0;
};

