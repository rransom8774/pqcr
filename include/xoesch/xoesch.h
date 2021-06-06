#ifndef Xuioiuxe51dh0lmqombc1wti3mqyofijcscuv7rml0t1nhegwawd8xwto2k3rhpcl
#define Xuioiuxe51dh0lmqombc1wti3mqyofijcscuv7rml0t1nhegwawd8xwto2k3rhpcl

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

struct xoesch256_state;
struct xoesch384_state;

size_t xoesch256_get_state_size();
size_t xoesch256_get_state_alignment();

void xoesch256_init(struct xoesch256_state *state);
int xoesch256_update(struct xoesch256_state *state, const uint8_t *inbuf, size_t len);
int xoesch256_finish_esch256(struct xoesch256_state *state, uint8_t *out);
int xoesch256_finish(struct xoesch256_state *state, uint8_t *out, size_t len);

void xoesch256_simple(struct xoesch256_state *state, uint8_t *out, size_t outlen, const uint8_t *inbuf, size_t inlen);
void xoesch256_simple_esch256(struct xoesch256_state *state, uint8_t *out, const uint8_t *inbuf, size_t inlen);

size_t xoesch384_get_state_size();
size_t xoesch384_get_state_alignment();

void xoesch384_init(struct xoesch384_state *state);
int xoesch384_update(struct xoesch384_state *state, const uint8_t *inbuf, size_t len);
int xoesch384_finish_esch384(struct xoesch384_state *state, uint8_t *out);
int xoesch384_finish(struct xoesch384_state *state, uint8_t *out, size_t len);

void xoesch384_simple(struct xoesch384_state *state, uint8_t *out, size_t outlen, const uint8_t *inbuf, size_t inlen);
void xoesch384_simple_esch384(struct xoesch384_state *state, uint8_t *out, const uint8_t *inbuf, size_t inlen);

#endif
