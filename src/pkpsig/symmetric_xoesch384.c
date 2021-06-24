
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

#include <xoesch/xoesch.h>

#include <stdlib.h>

static void xoesch384_XOF_chunked_input(struct pkpsig_scratch_store *st, unsigned char *output, size_t outputByteLen, const struct pkpsig_chunk *chunks, size_t chunkCount) {
  struct xoesch384_state *hst = st->algo_state;
  size_t i;

  xoesch384_init(hst);

  /* ignore return values here; these functions only report misuse errors */

  for (i = 0; i < chunkCount; ++i) {
    xoesch384_update(hst, chunks[i].buf, chunks[i].bytes);
  };

  xoesch384_finish(hst, output, outputByteLen);
};

static void xoesch384_hash_init(struct pkpsig_scratch_store *st, uint8_t context, const uint8_t *prefix, size_t prefix_len) {
  struct xoesch384_state *hst = st->algo_state_incremental;
  int rv = 0;

  xoesch384_init(hst);

  rv |= xoesch384_update(hst, &context, 1);
  rv |= xoesch384_update(hst, prefix, prefix_len);

  if (rv != 0) abort();
};

static void xoesch384_hash_index(struct pkpsig_scratch_store *st, uint32_t index) {
  struct xoesch384_state *hst = st->algo_state_incremental;
  int rv;
  uint8_t buf[4];

  pack_ui32(buf, index);
  rv = xoesch384_update(hst, buf, 4);

  if (rv != 0) abort();
};

static void xoesch384_hash_chunk(struct pkpsig_scratch_store *st, const uint8_t *chunk, size_t chunk_len) {
  struct xoesch384_state *hst = st->algo_state_incremental;
  int rv = xoesch384_update(hst, chunk, chunk_len);
  if (rv != 0) abort();
};

static void xoesch384_hash_ui16vec(struct pkpsig_scratch_store *st, const uint16_t *vec, size_t vec_len) {
  struct xoesch384_state *hst = st->algo_state_incremental;
  int rv;

  if (st->tmpbuf_bytes / 2 < vec_len) abort();
  pack_ui16vec(st->tmpbuf, vec, vec_len);

  rv = xoesch384_update(hst, st->tmpbuf, vec_len * 2);

  if (rv != 0) abort();
};

static void xoesch384_expand(struct pkpsig_scratch_store *st, uint8_t *output, size_t output_len) {
  struct xoesch384_state *hst = st->algo_state_incremental;
  int rv;

  rv = xoesch384_finish(hst, output, output_len);

  if (rv != 0) abort();
};

static struct pkpsig_symmetric_algo symalg_xoesch384 =
  {"xoesch384", 0,
   48, 48,
   pkpsig_generic_algo_state_alloc,
   pkpsig_generic_algo_state_set_prefix,
   pkpsig_generic_algo_state_use_prefix,
   pkpsig_generic_algo_state_zero,
   pkpsig_generic_algo_state_free,
   xoesch384_XOF_chunked_input,
   xoesch384_hash_init, xoesch384_hash_index, xoesch384_hash_chunk, xoesch384_hash_ui16vec,
   xoesch384_expand};

const struct pkpsig_symmetric_algo *pkpsig_symmetric_algo_get_xoesch384() {
  symalg_xoesch384.state_bytes = xoesch384_get_state_size();
  return &symalg_xoesch384;
};

