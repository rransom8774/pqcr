
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

#include <openssl/evp.h>

#include <assert.h>
#include <stdlib.h>

static int state_alloc_one(void **pptr) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  if (ctx == NULL) return -1;
  *pptr = ctx;

  if (EVP_DigestInit(ctx, EVP_shake256()) == 0) return -1;

  return 0;
};

static int state_alloc(struct pkpsig_scratch_store *st) {
  int rv = 0;
  rv |= state_alloc_one(&(st->algo_state));
  rv |= state_alloc_one(&(st->algo_state_incremental));
  rv |= state_alloc_one(&(st->algo_state_prefix));
  return rv;
};

static void state_set_prefix(struct pkpsig_scratch_store *st) {
  int rv;
  rv = EVP_MD_CTX_copy(st->algo_state_prefix, st->algo_state_incremental);
  if (rv == 0) abort();
};

static void state_use_prefix(struct pkpsig_scratch_store *st) {
  int rv;
  rv = EVP_MD_CTX_copy(st->algo_state_incremental, st->algo_state_prefix);
  if (rv == 0) abort();
};

static void state_zero(struct pkpsig_scratch_store *st) {
  int rv = 1;
  rv &= EVP_DigestInit(st->algo_state, EVP_shake256());
  rv &= EVP_DigestInit(st->algo_state_incremental, EVP_shake256());
  rv &= EVP_DigestInit(st->algo_state_prefix, EVP_shake256());
  if (rv == 0) abort();
};

static void state_free(struct pkpsig_scratch_store *st) {
  EVP_MD_CTX_free(st->algo_state);
  EVP_MD_CTX_free(st->algo_state_incremental);
  EVP_MD_CTX_free(st->algo_state_prefix);
};

static void shake256_XOF_chunked_input(struct pkpsig_scratch_store *st, unsigned char *output, size_t outputByteLen, const struct pkpsig_chunk *chunks, size_t chunkCount) {
  EVP_MD_CTX *ctx = st->algo_state;
  size_t i;

  if (EVP_DigestInit(ctx, EVP_shake256()) == 0) abort();

  for (i = 0; i < chunkCount; ++i) {
    if (EVP_DigestUpdate(ctx, chunks[i].buf, chunks[i].bytes) == 0) abort();
  };

  if (EVP_DigestFinalXOF(ctx, output, outputByteLen) == 0) abort();
};

static void shake256_hash_init(struct pkpsig_scratch_store *st, uint8_t context, const uint8_t *prefix, size_t prefix_len) {
  EVP_MD_CTX *ctx = st->algo_state_incremental;

  if (EVP_DigestInit(ctx, EVP_shake256()) == 0) abort();

  if (EVP_DigestUpdate(ctx, &context, 1) == 0) abort();
  if (EVP_DigestUpdate(ctx, prefix, prefix_len) == 0) abort();
};

static void shake256_hash_index(struct pkpsig_scratch_store *st, uint32_t index) {
  EVP_MD_CTX *ctx = st->algo_state_incremental;
  uint8_t buf[4];
  pack_ui32(buf, index);

  if (EVP_DigestUpdate(ctx, buf, 4) == 0) abort();
};

static void shake256_hash_chunk(struct pkpsig_scratch_store *st, const uint8_t *chunk, size_t chunk_len) {
  EVP_MD_CTX *ctx = st->algo_state_incremental;

  if (EVP_DigestUpdate(ctx, chunk, chunk_len) == 0) abort();
};

static void shake256_hash_ui16vec(struct pkpsig_scratch_store *st, const uint16_t *vec, size_t vec_len) {
  EVP_MD_CTX *ctx = st->algo_state_incremental;

  if (st->tmpbuf_bytes / 2 < vec_len) abort();
  pack_ui16vec(st->tmpbuf, vec, vec_len);

  if (EVP_DigestUpdate(ctx, st->tmpbuf, vec_len * 2) == 0) abort();
};

static void shake256_expand(struct pkpsig_scratch_store *st, uint8_t *output, size_t output_len) {
  EVP_MD_CTX *ctx = st->algo_state_incremental;

  if (EVP_DigestFinalXOF(ctx, output, output_len) == 0) abort();
};

static const struct pkpsig_symmetric_algo symalg_keccak_openssl =
  {"shake256", 0,
   64, 64,
   state_alloc,
   state_set_prefix,
   state_use_prefix,
   state_zero,
   state_free,
   shake256_XOF_chunked_input,
   shake256_hash_init, shake256_hash_index, shake256_hash_chunk, shake256_hash_ui16vec,
   shake256_expand};

const struct pkpsig_symmetric_algo *pkpsig_symmetric_algo_get_shake256() {
  return &symalg_keccak_openssl;
};

