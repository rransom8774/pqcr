
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

struct pkpsig_chunk {
  const uint8_t *buf;
  size_t bytes;
};

struct pkpsig_symmetric_algo {
  const char *name;
  const char *long_ui_name;
  const char *short_ui_name;
  size_t state_bytes;

  uint8_t max_seclevel_preimage_bytes;
  uint8_t max_seclevel_crhash_bytes;

  int (*algo_state_alloc)(struct pkpsig_scratch_store *st);
  void (*algo_state_set_prefix)(struct pkpsig_scratch_store *st);
  void (*algo_state_use_prefix)(struct pkpsig_scratch_store *st);
  void (*algo_state_zero)(struct pkpsig_scratch_store *st);
  void (*algo_state_free)(struct pkpsig_scratch_store *st);

  /* Chunk boundaries may or may not be preserved, depending on the
     underlying hash function or mode of operation. */

  void (*XOF_chunked_input)(struct pkpsig_scratch_store *st, unsigned char *output, size_t outputByteLen, const struct pkpsig_chunk *chunks, size_t chunkCount);

  void (*hash_init)(struct pkpsig_scratch_store *st, uint8_t context, const uint8_t *prefix, size_t prefix_len);
  void (*hash_index)(struct pkpsig_scratch_store *st, uint32_t index);
  void (*hash_chunk)(struct pkpsig_scratch_store *st, const uint8_t *chunk, size_t chunk_len);
  void (*hash_ui16vec)(struct pkpsig_scratch_store *st, const uint16_t *vec, size_t vec_len);
  void (*expand)(struct pkpsig_scratch_store *st, uint8_t *output, size_t output_len);
};

const struct pkpsig_symmetric_algo *pkpsig_symmetric_algo_get_shake256();
const struct pkpsig_symmetric_algo *pkpsig_symmetric_algo_get_xoesch256();
const struct pkpsig_symmetric_algo *pkpsig_symmetric_algo_get_xoesch384();

int pkpsig_generic_algo_state_alloc(struct pkpsig_scratch_store *st);
void pkpsig_generic_algo_state_set_prefix(struct pkpsig_scratch_store *st);
void pkpsig_generic_algo_state_use_prefix(struct pkpsig_scratch_store *st);
void pkpsig_generic_algo_state_zero(struct pkpsig_scratch_store *st);
void pkpsig_generic_algo_state_free(struct pkpsig_scratch_store *st);

void pkpsig_scratch_store_set_prefix(struct pkpsig_scratch_store *st);
void pkpsig_scratch_store_use_prefix(struct pkpsig_scratch_store *st);
void pkpsig_scratch_store_zero_algo_state(struct pkpsig_scratch_store *st);

#define PERMSAMPLER_RANDOM_MASK 0xFFFFFF80
#define PERMSAMPLER_INDEX_MASK  0x0000007F

#define HASHCTX_PUBPARAMS 0
#define HASHCTX_SECKEYSEEDEXPAND 1
#define HASHCTX_SECKEYCHECKSUM 2
#define HASHCTX_MESSAGEHASH 3
#define HASHCTX_EXPANDBLINDINGSEED 4
#define HASHCTX_COMMITMENT 5
#define HASHCTX_CHALLENGE1HASH 6
#define HASHCTX_CHALLENGE1EXPAND 7
#define HASHCTX_CHALLENGE2HASH 8
#define HASHCTX_CHALLENGE2EXPAND 9

#define HASHCTX_INTERNAL_GENMSGHASHSALT 0x80
#define HASHCTX_INTERNAL_GENBLINDINGSEEDGENSEED 0x81
#define HASHCTX_INTERNAL_GENBLINDINGSEED 0x82

#define HASHIDX_SECKEYSEEDEXPAND_PI_INV 0
#define HASHIDX_SECKEYSEEDEXPAND_PUBPARAMSSEED 1

#define HASHIDX_EXPANDBLINDINGSEED_RUN_INDEX_FACTOR 256
#define HASHIDX_EXPANDBLINDINGSEED_COMMITMENT 0
#define HASHIDX_EXPANDBLINDINGSEED_PI_SIGMA_INV 1
#define HASHIDX_EXPANDBLINDINGSEED_R_SIGMA 2

#include "symmetric_endian.h"

