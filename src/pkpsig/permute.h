#ifndef Xru36ysaz0nmjpfxlhop0t0ai6gcc0v6oton8r2ij0zgsj4iwpronjibyy323b91d
#define Xru36ysaz0nmjpfxlhop0t0ai6gcc0v6oton8r2ij0zgsj4iwpronjibyy323b91d

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

struct pkpsig_scratch_store;

/* maximum vector element size is 12 bits; maximum length is 128 */

void pkpsig_permute_prepare(struct pkpsig_scratch_store *st);

void pkpsig_permute_apply_inv(struct pkpsig_scratch_store *st, uint16_t *v_sigma, const uint16_t *v, const uint8_t *sigma_inv);

void pkpsig_permute_apply_and_compose_inv(struct pkpsig_scratch_store *st, uint16_t *v_sigma, uint8_t *pi_sigma, const uint16_t *v, const uint8_t *pi, const uint8_t *sigma_inv);

void pkpsig_perm_squish(struct pkpsig_scratch_store *st, uint8_t *sigma);
void pkpsig_perm_unsquish(struct pkpsig_scratch_store *st, uint8_t *sigma);

#endif
