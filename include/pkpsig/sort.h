#ifndef X7g00uyohujcwq29508tjkprw2m6jkrz80a2tu87bd7ldhkn3bkua9q25grnun5y0
#define X7g00uyohujcwq29508tjkprw2m6jkrz80a2tu87bd7ldhkn3bkua9q25grnun5y0

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

size_t pkpsig_sort_anyint32_get_pad_length(size_t veclen);
size_t pkpsig_sort_uint32_pad_sortbuf(uint32_t *buf, size_t veclen);
size_t pkpsig_sort_posint32_pad_sortbuf(uint32_t *buf, size_t veclen);

void pkpsig_sort_uint32(uint32_t *buf, size_t padlen);
void pkpsig_sort_posint32(uint32_t *buf, size_t padlen);

struct pkpsig_sort_blob {
  uint32_t key;
  uint8_t *value;
};

void pkpsig_batcher_merge_blob(struct pkpsig_sort_blob *blobs, int mergelen_l2, size_t nblobs, size_t value_bytes);
void pkpsig_sort_blob(struct pkpsig_sort_blob *blobs, size_t nblobs, size_t value_bytes);

#endif
