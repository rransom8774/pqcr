
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

/* key allocation functions will ensure A_stride has this many zero LSbs */
#define PKPSIG_MATRIX_COLUMN_ALIGNMENT_BITS 0

int pkpsig_key_unpack_skblob_internal(struct pkpsig_scratch_store *st, struct pkpsig_keysecret *key);

