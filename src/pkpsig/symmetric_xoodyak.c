
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

#include <XKCP/Xoodyak.h>

#include <assert.h>
#include <stdlib.h>

static void xoodyak_XOF_chunked_input(struct pkpsig_scratch_store *st, unsigned char *output, size_t outputByteLen, const struct pkpsig_chunk *chunks, size_t chunkCount) {
  Xoodyak_Instance *hst = st->algo_state;
  size_t i;

  Xoodyak_Initialize(hst, NULL, 0, NULL, 0, NULL, 0);

  for (i = 0; i < chunkCount; ++i) {
    Xoodyak_Absorb(hst, chunks[i].buf, chunks[i].bytes);
  };

  Xoodyak_Squeeze(hst, output, outputByteLen);
};

static void xoodyak_XOF(struct pkpsig_scratch_store *st, unsigned char *output, size_t outputByteLen, const unsigned char *input, size_t inputByteLen) {
  Xoodyak_Instance *hst = st->algo_state;

  Xoodyak_Initialize(hst, NULL, 0, NULL, 0, NULL, 0);
  Xoodyak_Absorb(hst, input, inputByteLen);
  Xoodyak_Squeeze(hst, output, outputByteLen);
};

static void xoodyak_hash_init(struct pkpsig_scratch_store *st, uint8_t context, const uint8_t *prefix, size_t prefix_len) {
  Xoodyak_Instance *hst = st->algo_state_incremental;

  Xoodyak_Initialize(hst, NULL, 0, NULL, 0, NULL, 0);
  Xoodyak_Absorb(hst, &context, 1);
  Xoodyak_Absorb(hst, prefix, prefix_len);
};

static void xoodyak_hash_index(struct pkpsig_scratch_store *st, uint32_t index) {
  Xoodyak_Instance *hst = st->algo_state_incremental;
  uint8_t buf[4];

  pack_ui32(buf, index);
  Xoodyak_Absorb(hst, buf, 4);
};

static void xoodyak_hash_chunk(struct pkpsig_scratch_store *st, const uint8_t *chunk, size_t chunk_len) {
  Xoodyak_Instance *hst = st->algo_state_incremental;

  Xoodyak_Absorb(hst, chunk, chunk_len);
};

static void xoodyak_hash_ui16vec(struct pkpsig_scratch_store *st, const uint16_t *vec, size_t vec_len) {
  Xoodyak_Instance *hst = st->algo_state_incremental;

  if (st->tmpbuf_bytes / 2 < vec_len) abort();
  pack_ui16vec(st->tmpbuf, vec, vec_len);

  Xoodyak_Absorb(hst, st->tmpbuf, vec_len * 2);
};

static void xoodyak_expand(struct pkpsig_scratch_store *st, uint8_t *output, size_t output_len) {
  Xoodyak_Instance *hst = st->algo_state_incremental;

  Xoodyak_Squeeze(hst, output, output_len);
};

static const struct pkpsig_symmetric_algo symalg_xoodyak =
  {"xoodyak", sizeof(Xoodyak_Instance),
   xoodyak_XOF, xoodyak_XOF_chunked_input,
   xoodyak_hash_init, xoodyak_hash_index, xoodyak_hash_chunk, xoodyak_hash_ui16vec,
   xoodyak_expand};

const struct pkpsig_symmetric_algo *pkpsig_symmetric_algo_get_xoodyak() {
  return &symalg_xoodyak;
};

