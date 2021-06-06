
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "symmetric.h"

#include "symmetric_internal.h"

#include <XKCP/KeccakSponge.h>

#include <assert.h>
#include <stdlib.h>

/* The simplest way to hash strings would be to use the nice, simple,
   easy SHAKE256 function in SimpleFIPS202.[hc], which takes one input
   and one output buffer along with their lengths in bytes.
   Unfortunately, we need to hash a message from a user-provided
   buffer along with two different prefix strings, and in one case a
   suffix string as well, and neither requiring the user to provide
   extra scratch space at the beginning of the message (as the
   SUPERCOP interface requires) nor copying the message are acceptable
   in a general-purpose signature implementation.

   Ideally, we would be able to use the routines in KeccakHash.[hc]
   from the same FIPS202 directory of the XKCP source tree.
   Unfortunately, those take input and output lengths in bits, not
   bytes, and trying to use that interface to process the byte-counted
   buffers that any sane piece of software would operate on is either
   a mess or a disaster waiting to be exploited.  The Keccak authors
   knew better than to even try to use their NIST-mandated bit-length
   interface in KeccakHash.h to implement their SimpleFIPS202 routines.

   So, use the KeccakSponge.[hc] interface that SimpleFIPS202.c is
   implemented on top of.  That module does not provide convenience
   functions to pass in the NIST-standard constants or finalization
   padding as the KeccakHash module does, but putting a few magic
   numbers in the code is the least horrid option NIST and the Keccak
   authors gave us. */

static void shake256_XOF_chunked_input(struct pkpsig_scratch_store *st, unsigned char *output, size_t outputByteLen, const struct pkpsig_chunk *chunks, size_t chunkCount) {
  KeccakWidth1600_SpongeInstance *hst = st->algo_state;
  int rv = 0;
  size_t i;

  /* 1088 and 512 are the rate and capacity, respectively.  They are
     passed to the routine in bits, even though the implementation
     only supports integral numbers of bytes. */
  rv |= KeccakWidth1600_SpongeInitialize(hst, 1088, 512);

  for (i = 0; i < chunkCount; ++i) {
    rv |= KeccakWidth1600_SpongeAbsorb(hst, chunks[i].buf, chunks[i].bytes);
  };

  /* 0x1F is the suffix for SHAKE256. */
  rv |= KeccakWidth1600_SpongeAbsorbLastFewBits(hst, 0x1F);

  rv |= KeccakWidth1600_SpongeSqueeze(hst, output, outputByteLen);

  /* The only errors these functions can report are misuse errors. */
  if (rv != 0) abort();
};

static void shake256_hash_init(struct pkpsig_scratch_store *st, uint8_t context, const uint8_t *prefix, size_t prefix_len) {
  KeccakWidth1600_SpongeInstance *hst = st->algo_state_incremental;
  int rv = 0;

  /* 1088 and 512 are the rate and capacity, respectively.  They are
     passed to the routine in bits, even though the implementation
     only supports integral numbers of bytes. */
  rv |= KeccakWidth1600_SpongeInitialize(hst, 1088, 512);

  rv |= KeccakWidth1600_SpongeAbsorb(hst, &context, 1);
  rv |= KeccakWidth1600_SpongeAbsorb(hst, prefix, prefix_len);

  if (rv != 0) abort();
};

static void shake256_hash_index(struct pkpsig_scratch_store *st, uint32_t index) {
  KeccakWidth1600_SpongeInstance *hst = st->algo_state_incremental;
  int rv = 0;
  uint8_t buf[4];

  pack_ui32(buf, index);
  rv |= KeccakWidth1600_SpongeAbsorb(hst, buf, 4);

  if (rv != 0) abort();
};

static void shake256_hash_chunk(struct pkpsig_scratch_store *st, const uint8_t *chunk, size_t chunk_len) {
  KeccakWidth1600_SpongeInstance *hst = st->algo_state_incremental;
  int rv = 0;

  rv |= KeccakWidth1600_SpongeAbsorb(hst, chunk, chunk_len);

  if (rv != 0) abort();
};

static void shake256_hash_ui16vec(struct pkpsig_scratch_store *st, const uint16_t *vec, size_t vec_len) {
  KeccakWidth1600_SpongeInstance *hst = st->algo_state_incremental;
  int rv = 0;

  if (st->tmpbuf_bytes / 2 < vec_len) abort();
  pack_ui16vec(st->tmpbuf, vec, vec_len);

  rv |= KeccakWidth1600_SpongeAbsorb(hst, st->tmpbuf, vec_len * 2);

  if (rv != 0) abort();
};

static void shake256_expand(struct pkpsig_scratch_store *st, uint8_t *output, size_t output_len) {
  KeccakWidth1600_SpongeInstance *hst = st->algo_state_incremental;
  int rv = 0;

  rv |= KeccakWidth1600_SpongeAbsorbLastFewBits(hst, 0x1F);
  rv |= KeccakWidth1600_SpongeSqueeze(hst, output, output_len);

  if (rv != 0) abort();
};

static const struct pkpsig_symmetric_algo symalg_keccak =
  {"shake256", sizeof(KeccakWidth1600_SpongeInstance),
   shake256_XOF_chunked_input,
   shake256_hash_init, shake256_hash_index, shake256_hash_chunk, shake256_hash_ui16vec,
   shake256_expand};

const struct pkpsig_symmetric_algo *pkpsig_symmetric_algo_get_shake256() {
  return &symalg_keccak;
};

