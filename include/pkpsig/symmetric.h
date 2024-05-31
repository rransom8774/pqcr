#ifndef Xv1hw0nq676h4swc5285bui85pgbacsv5c233fa64tjkph6lse1hwmqvziq42koa6
#define Xv1hw0nq676h4swc5285bui85pgbacsv5c233fa64tjkph6lse1hwmqvziq42koa6

/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include <stddef.h>
#include <stdint.h>

struct pkpsig_symmetric_algo; /* algorithm vtable; statically allocated */

struct pkpsig_paramset;
struct pkpsig_keyparams;
struct pkpsig_keysecret;
struct pkpsig_sigstate;

struct pkpsig_scratch_store { /* one per thread */
  const struct pkpsig_symmetric_algo *algo;
  void *algo_state;
  void *algo_state_incremental;
  void *algo_state_prefix;

  const struct pkpsig_paramset *ps; /* must be set by _set_paramset */

  size_t output_bytes, tmpbuf_bytes;
  size_t vec_elts;
  size_t treehash_buf_bytes;
  size_t treehash_leaf_count;

  uint8_t *outputbuf;
  uint8_t *tmpbuf;
  uint32_t *vecbuf; /* big enough for a sort call on max(n, m) words */

  uint8_t *treehash_buf;
  struct pkpsig_sort_blob *treehash_leaves;
  size_t treehash_node_count;
  size_t treehash_node_bytes;
  uint32_t treehash_next_header_index;
  uint8_t treehash_params[7];
  uint8_t treehash_context;
  const uint8_t *treehash_prefix;
  size_t treehash_prefix_bytes;
};

typedef int (*pkpsig_symmetric_algo_enumerate_names_cb)(void *ud, const char *name);

const struct pkpsig_symmetric_algo *pkpsig_symmetric_algo_get(const char *name);
int pkpsig_symmetric_algo_enumerate_names(pkpsig_symmetric_algo_enumerate_names_cb cb, void *ud);
const char *pkpsig_symmetric_algo_name(const struct pkpsig_symmetric_algo *algo);
const char *pkpsig_symmetric_algo_ui_name_short(const struct pkpsig_symmetric_algo *algo);
const char *pkpsig_symmetric_algo_ui_name_long(const struct pkpsig_symmetric_algo *algo);
size_t pkpsig_symmetric_algo_state_bytes(const struct pkpsig_symmetric_algo *algo);
int pkpsig_symmetric_algo_check_seclevel(const struct pkpsig_symmetric_algo *algo, int preimage_bytes, int crhash_bytes);

struct pkpsig_scratch_store *pkpsig_scratch_store_new(const struct pkpsig_symmetric_algo *algo);
void pkpsig_scratch_store_set_paramset(struct pkpsig_scratch_store *st, const struct pkpsig_paramset *ps);
int pkpsig_scratch_store_alloc_bufs(struct pkpsig_scratch_store *st);

void pkpsig_scratch_store_zero_bufs(struct pkpsig_scratch_store *st);
void pkpsig_scratch_store_free_bufs(struct pkpsig_scratch_store *st);
void pkpsig_scratch_store_free(struct pkpsig_scratch_store *st);

void pkpsig_symmetric_expand_A(struct pkpsig_scratch_store *st, struct pkpsig_keyparams *kp, const uint8_t *seed);

void pkpsig_symmetric_expand_pi_inv(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key, const uint8_t *seed);
void pkpsig_symmetric_expand_pubparamseed_from_seckeyseed(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key, const uint8_t *seed);

void pkpsig_symmetric_gen_msghash_salt(struct pkpsig_sigstate *sst, const uint8_t *message, size_t messagelen);

void pkpsig_symmetric_hash_message(struct pkpsig_sigstate *sst, const uint8_t *message, size_t messagelen);

void pkpsig_symmetric_gen_blindingseeds(struct pkpsig_sigstate *sst);
void pkpsig_symmetric_expand_blindingseeds(struct pkpsig_sigstate *sst);

void pkpsig_symmetric_gen_com1s(struct pkpsig_sigstate *sst, int verifying);

void pkpsig_symmetric_hash_commit1s(struct pkpsig_sigstate *sst, uint8_t *outbuf, int verifying);
void pkpsig_symmetric_expand_challenge1s(struct pkpsig_sigstate *sst, int verifying);

void pkpsig_symmetric_hash_commit2s(struct pkpsig_sigstate *sst, uint8_t *outbuf, int verifying);
void pkpsig_symmetric_expand_challenge2s(struct pkpsig_sigstate *sst, int verifying);

#endif
