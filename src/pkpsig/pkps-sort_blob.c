
/*
 * Authors: D. J. Bernstein (djbsort-20190516); minor changes by Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "sort.h"

#include "sort_minmax_blob.h"

/* copied from djbsort-20190516 int32/portable4/sort.c, mutandis mutatis */
void pkpsig_sort_blob(struct pkpsig_sort_blob *blobs, size_t nblobs, size_t value_bytes) {
  size_t n = nblobs;
  size_t top,p,q,r,i,j;

  if (n < 2) return;
  top = 1;
  while (top < n - top) top += top;

  for (p = top;p >= 1;p >>= 1) {
    i = 0;
    while (i + 2 * p <= n) {
      for (j = i;j < i + p;++j)
        blob_minmax(&(blobs[j]), &(blobs[j+p]), value_bytes);
      i += 2 * p;
    }
    for (j = i;j < n - p;++j)
      blob_minmax(&(blobs[j]), &(blobs[j+p]), value_bytes);

    i = 0;
    j = 0;
    for (q = top;q > p;q >>= 1) {
      if (j != i) for (;;) {
        if (j == n - q) goto done;
        for (r = q;r > p;r >>= 1)
          blob_minmax(&(blobs[j + p]), &(blobs[j + r]), value_bytes);
        ++j;
        if (j == i + p) {
          i += 2 * p;
          break;
        }
      }
      while (i + p <= n - q) {
        for (j = i;j < i + p;++j) {
          for (r = q;r > p;r >>= 1)
            blob_minmax(&(blobs[j+p]), &(blobs[j+r]), value_bytes);
        }
        i += 2 * p;
      }
      /* now i + p > n - q */
      j = i;
      while (j < n - q) {
        for (r = q;r > p;r >>= 1)
          blob_minmax(&(blobs[j+p]), &(blobs[j+r]), value_bytes);
        ++j;
      }

      done: ;
    }
  }
};

