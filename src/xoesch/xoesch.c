
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include <xoesch/xoesch.h>

#include <string.h>

#include <assert.h>

static const uint32_t branch_constants[8] = {
  0xB7E15162, 0xBF715880,
  0x38B4DA56, 0x324E7738,
  0xBB1185EB, 0x4F7C7B57,
  0xCFBFA1C8, 0xC2B3293D,
};

#define SPARKLE384_BRANCHES 6
#define SPARKLE384_STATE_WORDS (SPARKLE384_BRANCHES*2)
#define SPARKLE384_ROUNDS_SLIM 7
#define SPARKLE384_ROUNDS_BIG 11
#define SPARKLE384_INJECT_BRANCHES 3

#define SPARKLE512_BRANCHES 8
#define SPARKLE512_STATE_WORDS (SPARKLE512_BRANCHES*2)
#define SPARKLE512_ROUNDS_SLIM 8
#define SPARKLE512_ROUNDS_BIG 12
#define SPARKLE512_INJECT_BRANCHES 4

#define BLOCK_INJECT_WORDS (SPARKLE512_INJECT_BRANCHES*2)
#define BLOCK_WORDS 4
#define BLOCK_BYTES (BLOCK_WORDS * 4)

struct xoesch_common_state {
  uint32_t message_inject_buf[BLOCK_INJECT_WORDS];
  uint8_t message_buf_pos;
  uint8_t finished;
  uint8_t message_buf[BLOCK_BYTES];
};

struct xoesch256_state {
  struct xoesch_common_state com;
  uint32_t sparkle_state[SPARKLE384_STATE_WORDS];
};

struct xoesch384_state {
  struct xoesch_common_state com;
  uint32_t sparkle_state[SPARKLE512_STATE_WORDS];
};

/* XXX pack/unpack should be replaced with target-specific versions. */

static inline void pack_ui32(uint8_t *buf, uint32_t x) {
  buf[0] =  x        & 255;
  buf[1] = (x >>  8) & 255;
  buf[2] = (x >> 16) & 255;
  buf[3] = (x >> 24) & 255;
};

static inline void unpack_ui32vec(uint32_t *v, const uint8_t *buf, size_t n) {
  size_t i;

  for (i = 0; i < n; ++i) {
    v[i] = (( ((uint32_t)buf[(4*i)+0])       ) +
	    ((((uint32_t)buf[(4*i)+1]) <<  8)) +
	    ((((uint32_t)buf[(4*i)+2]) << 16)) +
	    ((((uint32_t)buf[(4*i)+3]) << 24)));
  };
};

/* XXX ror should be replaced with a compiler-specific version. */

static inline uint32_t ror32(uint32_t x, unsigned int shift) {
  /* breaks if shift is not in the interval [1, 31] */
  return ((x >> shift) | (x << (32 - shift)));
};

static void alzette(uint32_t *z, uint32_t c) {
  uint32_t x = z[0];
  uint32_t y = z[1];

  x += ror32(y, 31);
  y ^= ror32(x, 24);
  x ^= c;
  x += ror32(y, 17);
  y ^= ror32(x, 17);
  x ^= c;
  x += y;
  y ^= ror32(x, 31);
  x ^= c;
  x += ror32(y, 24);
  y ^= ror32(x, 16);
  x ^= c;

  z[0] = x;
  z[1] = y;
};

static inline uint32_t l(uint32_t x) {
  /* ror32 by 16 is equivalent to rotating left by 16 */
  return ror32(x, 16) ^ (x & 0xFFFF);
};

static void M(uint32_t *dest, const uint32_t *src, unsigned int h) {
  unsigned int i;
  uint32_t sum_x = 0;
  uint32_t sum_y = 0;
  uint32_t l_sum_x, l_sum_y;

  for (i = 0; i < h; ++i) {
    uint32_t x = src[(2*i) + 0];
    uint32_t y = src[(2*i) + 1];
    sum_x ^= x;
    sum_y ^= y;
  };

  l_sum_x = l(sum_x);
  l_sum_y = l(sum_y);

  for (i = 0; i < h; ++i) {
    uint32_t x = src[(2*i) + 0];
    uint32_t y = src[(2*i) + 1];
    uint32_t u = x ^ l_sum_y;
    uint32_t v = y ^ l_sum_x;
    dest[(2*i) + 0] ^= u;
    dest[(2*i) + 1] ^= v;
  };
};

static void L(uint32_t *array, unsigned int n) {
  unsigned int h = n/2;
  unsigned int i;
  uint32_t tmp_x, tmp_y;

  assert((n & 1) == 0);

  M(array + n, array, h); /* n = 2*h */

  tmp_x = array[n + 0]; /* n = 2*h */
  tmp_y = array[n + 1];

  for (i = 0; i < h-1; ++i) {
    array[(2*(i+h)) + 0] = array[(2*i) + 0];
    array[(2*(i+h)) + 1] = array[(2*i) + 1];

    array[(2*i) + 0] = array[(2*(i+h+1)) + 0];
    array[(2*i) + 1] = array[(2*(i+h+1)) + 1];
  };

  array[(2*(n-1)) + 0] = array[(2*(h-1)) + 0];
  array[(2*(n-1)) + 1] = array[(2*(h-1)) + 1];

  array[(n-2) + 0] = tmp_x; /* n-2 = 2*(h-1) */
  array[(n-2) + 1] = tmp_y;
};

static void Sparkle(uint32_t *array, unsigned int n_b, unsigned int n_s) {
  unsigned int s, i;

  for (s = 0; s < n_s; ++s) {
    array[1] /* y_0 */ ^= branch_constants[s & 7];
    array[3] /* y_1 */ ^= s;

    for (i = 0; i < n_b; ++i) {
      alzette(array + (2*i), branch_constants[i]);
    };

    L(array, n_b);
  };
};

static void x256_process_block_noinject(struct xoesch256_state *state) {
  Sparkle(state->sparkle_state, SPARKLE384_BRANCHES, SPARKLE384_ROUNDS_SLIM);
};

static void x256_process_block(struct xoesch256_state *state) {
  unpack_ui32vec(state->com.message_inject_buf, state->com.message_buf, BLOCK_WORDS);
  M(state->sparkle_state, state->com.message_inject_buf, SPARKLE384_INJECT_BRANCHES);
  return x256_process_block_noinject(state);
};

static void x256_process_block_big(struct xoesch256_state *state, uint8_t const_M) {
  unpack_ui32vec(state->com.message_inject_buf, state->com.message_buf, BLOCK_WORDS);
  M(state->sparkle_state, state->com.message_inject_buf, SPARKLE384_INJECT_BRANCHES);

  /* The spec claims that Const_M is to be some number shifted left by
     256 bits (for Esch384/XOEsch384), which puts it in the capacity
     of the sponge as the paper states.  The reference implementation,
     however, XORs the constant byte into the last byte modified by
     message injection. */

  state->sparkle_state[(SPARKLE384_STATE_WORDS / 2) - 1] ^=
    (((uint32_t)const_M) << 24);

  Sparkle(state->sparkle_state, SPARKLE384_BRANCHES, SPARKLE384_ROUNDS_BIG);
};

static void x384_process_block_noinject(struct xoesch384_state *state) {
  Sparkle(state->sparkle_state, SPARKLE512_BRANCHES, SPARKLE512_ROUNDS_SLIM);
};

static void x384_process_block(struct xoesch384_state *state) {
  unpack_ui32vec(state->com.message_inject_buf, state->com.message_buf, BLOCK_WORDS);
  M(state->sparkle_state, state->com.message_inject_buf, SPARKLE512_INJECT_BRANCHES);
  return x384_process_block_noinject(state);
};

static void x384_process_block_big(struct xoesch384_state *state, uint8_t const_M) {
  unpack_ui32vec(state->com.message_inject_buf, state->com.message_buf, BLOCK_WORDS);
  M(state->sparkle_state, state->com.message_inject_buf, SPARKLE512_INJECT_BRANCHES);

  /* The spec claims that Const_M is to be some number shifted left by
     256 bits (for Esch384/XOEsch384), which puts it in the capacity
     of the sponge as the paper states.  The reference implementation,
     however, XORs the constant byte into the last byte modified by
     message injection. */

  state->sparkle_state[(SPARKLE512_STATE_WORDS / 2) - 1] ^=
    (((uint32_t)const_M) << 24);

  Sparkle(state->sparkle_state, SPARKLE512_BRANCHES, SPARKLE512_ROUNDS_BIG);
};

static int pad_message_block(struct xoesch_common_state *stcom) {
  if (stcom->message_buf_pos == 16) return 0;

  /* The spec claims that all bitstrings/numbers are little-endian,
     and specifies that padding sets the next (i.e. low) bit after a
     partial message block, but the reference implementation sets the
     high bit of the pad byte instead. */

  stcom->message_buf[stcom->message_buf_pos] = 0x80;
  memset(stcom->message_buf + stcom->message_buf_pos + 1, 0,
	 BLOCK_BYTES - (stcom->message_buf_pos + 1));

  return 1;
};

void x256_output_block(struct xoesch256_state *state) {
  size_t i;

  for (i = 0; i < (BLOCK_BYTES / 4); ++i) {
    pack_ui32(state->com.message_buf + (4*i), state->sparkle_state[i]);
  };
};

void x384_output_block(struct xoesch384_state *state) {
  size_t i;

  for (i = 0; i < (BLOCK_BYTES / 4); ++i) {
    pack_ui32(state->com.message_buf + (4*i), state->sparkle_state[i]);
  };
};

size_t xoesch256_get_state_size() { return sizeof(struct xoesch256_state); };
size_t xoesch256_get_state_alignment() { return sizeof(uint32_t); };

size_t xoesch384_get_state_size() { return sizeof(struct xoesch384_state); };
size_t xoesch384_get_state_alignment() { return sizeof(uint32_t); };

void xoesch256_init(struct xoesch256_state *state) {
  int i;
  for (i = 0; i < SPARKLE384_STATE_WORDS; ++i) state->sparkle_state[i] = 0;
  for (i = 0; i < BLOCK_INJECT_WORDS; ++i) state->com.message_inject_buf[i] = 0;
  for (i = 0; i < BLOCK_BYTES; ++i) state->com.message_buf[i] = 0;
  state->com.message_buf_pos = 0;
  state->com.finished = 0;
};

void xoesch384_init(struct xoesch384_state *state) {
  int i;
  for (i = 0; i < SPARKLE512_STATE_WORDS; ++i) state->sparkle_state[i] = 0;
  for (i = 0; i < BLOCK_INJECT_WORDS; ++i) state->com.message_inject_buf[i] = 0;
  for (i = 0; i < BLOCK_BYTES; ++i) state->com.message_buf[i] = 0;
  state->com.message_buf_pos = 0;
  state->com.finished = 0;
};

static void buffer_message(struct xoesch_common_state *stcom, const uint8_t **inbuf, size_t *len) {
  size_t to_copy = BLOCK_BYTES - (size_t)(stcom->message_buf_pos);
  to_copy = ((to_copy > *len) ? (*len) : (to_copy));

  memcpy(stcom->message_buf + stcom->message_buf_pos, *inbuf, to_copy);

  *inbuf += to_copy;
  stcom->message_buf_pos += to_copy;
  *len -= to_copy;
};

int xoesch256_update(struct xoesch256_state *state, const uint8_t *inbuf, size_t len) {
  if (state->com.finished != 0) return -1;

  buffer_message(&(state->com), &inbuf, &len);
  if (len == 0) return 0;

  /* state->com.message_buf_pos == BLOCK_BYTES */

  while (len > BLOCK_BYTES) {
    x256_process_block(state);

    memcpy(state->com.message_buf, inbuf, BLOCK_BYTES);
    state->com.message_buf_pos = BLOCK_BYTES;
    inbuf += BLOCK_BYTES;
    len -= BLOCK_BYTES;
  };

  /* state->com.message_buf_pos == BLOCK_BYTES && len > 0 */

  assert(state->com.message_buf_pos == BLOCK_BYTES && len > 0);

  x256_process_block(state);

  /* state->com.message_buf_pos == 0 && len <= BLOCK_BYTES */

  memcpy(state->com.message_buf, inbuf, len);
  state->com.message_buf_pos = len;

  return 0;
};

int xoesch384_update(struct xoesch384_state *state, const uint8_t *inbuf, size_t len) {
  if (state->com.finished != 0) return -1;

  buffer_message(&(state->com), &inbuf, &len);
  if (len == 0) return 0;

  /* state->com.message_buf_pos == BLOCK_BYTES */

  while (len > BLOCK_BYTES) {
    x384_process_block(state);

    memcpy(state->com.message_buf, inbuf, BLOCK_BYTES);
    state->com.message_buf_pos = BLOCK_BYTES;
    inbuf += BLOCK_BYTES;
    len -= BLOCK_BYTES;
  };

  /* state->com.message_buf_pos == BLOCK_BYTES && len > 0 */

  assert(state->com.message_buf_pos == BLOCK_BYTES && len > 0);

  x384_process_block(state);

  /* state->com.message_buf_pos == 0 && len <= BLOCK_BYTES */

  memcpy(state->com.message_buf, inbuf, len);
  state->com.message_buf_pos = len;

  return 0;
};

static int x256_finish_internal(struct xoesch256_state *state, uint8_t *out, size_t len, uint8_t const_M) {
  int padded;

  if (state->com.finished != 0) return -1;
  state->com.finished = 1;

  padded = pad_message_block(&(state->com));
  x256_process_block_big(state, (padded ? 1 : 2) ^ const_M);

  while (len > BLOCK_BYTES) {
    x256_output_block(state);
    memcpy(out, state->com.message_buf, BLOCK_BYTES);
    out += BLOCK_BYTES; len -= BLOCK_BYTES;

    x256_process_block_noinject(state);
  };

  /* len <= BLOCK_BYTES */

  x256_output_block(state);
  memcpy(out, state->com.message_buf, len);

  return 0;
};

int xoesch256_finish_esch256(struct xoesch256_state *state, uint8_t *out) {
  return x256_finish_internal(state, out, 32, 0);
};

int xoesch256_finish(struct xoesch256_state *state, uint8_t *out, size_t len) {
  return x256_finish_internal(state, out, len, 4);
};

static int x384_finish_internal(struct xoesch384_state *state, uint8_t *out, size_t len, uint8_t const_M) {
  int padded;

  if (state->com.finished != 0) return -1;
  state->com.finished = 1;

  padded = pad_message_block(&(state->com));
  x384_process_block_big(state, (padded ? 1 : 2) ^ const_M);

  while (len > BLOCK_BYTES) {
    x384_output_block(state);
    memcpy(out, state->com.message_buf, BLOCK_BYTES);
    out += BLOCK_BYTES; len -= BLOCK_BYTES;

    x384_process_block_noinject(state);
  };

  /* len <= BLOCK_BYTES */

  x384_output_block(state);
  memcpy(out, state->com.message_buf, len);

  return 0;
};

int xoesch384_finish_esch384(struct xoesch384_state *state, uint8_t *out) {
  return x384_finish_internal(state, out, 48, 0);
};

int xoesch384_finish(struct xoesch384_state *state, uint8_t *out, size_t len) {
  return x384_finish_internal(state, out, len, 4);
};

void xoesch256_simple(struct xoesch256_state *state, uint8_t *out, size_t outlen, const uint8_t *inbuf, size_t inlen) {
  int rv;
  xoesch256_init(state);
  rv = xoesch256_update(state, inbuf, inlen);
  rv |= xoesch256_finish(state, out, outlen);
  assert(rv == 0);
};

void xoesch256_simple_esch256(struct xoesch256_state *state, uint8_t *out, const uint8_t *inbuf, size_t inlen) {
  int rv;
  xoesch256_init(state);
  rv = xoesch256_update(state, inbuf, inlen);
  rv |= xoesch256_finish_esch256(state, out);
  assert(rv == 0);
};

void xoesch384_simple(struct xoesch384_state *state, uint8_t *out, size_t outlen, const uint8_t *inbuf, size_t inlen) {
  int rv;
  xoesch384_init(state);
  rv = xoesch384_update(state, inbuf, inlen);
  rv |= xoesch384_finish(state, out, outlen);
  assert(rv == 0);
};

void xoesch384_simple_esch384(struct xoesch384_state *state, uint8_t *out, const uint8_t *inbuf, size_t inlen) {
  int rv;
  xoesch384_init(state);
  rv = xoesch384_update(state, inbuf, inlen);
  rv |= xoesch384_finish_esch384(state, out);
  assert(rv == 0);
};

