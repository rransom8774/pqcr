
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "sort.h"

#include "sort_minmax_blob.h"

/* Given two sorted sequences of length baselen := 1<<(mergelen_l2-1)
 * starting at indices off and off+baselen, merge them into one sorted
 * sequence of length 1<<mergelen_l2, in data-independent time. */
void pkpsig_batcher_merge_blob(struct pkpsig_sort_blob *blobs, int mergelen_l2, size_t nblobs, size_t value_bytes) {
  int merge_layer;    /* step within the merge; counts down */
  size_t stride,      /* distance between minmax endpoints */
         chunkstart,  /* start of a chunk of conditional swaps */
         firstchunk,  /* start of the first chunk within the layer */
         icswap;      /* index of the current cswap after chunkstart */

  {
    size_t mergelen = ((size_t) 1) << mergelen_l2;
    if (nblobs > mergelen) nblobs = mergelen;
  };

  for (merge_layer = mergelen_l2 - 1, firstchunk=0, stride = 1<<merge_layer;
       merge_layer >= 0;
       --merge_layer, firstchunk = stride = 1<<merge_layer) {
    for (chunkstart = firstchunk;
         chunkstart + stride < nblobs;
         chunkstart += stride<<1) {
      for (icswap = 0;
           icswap < stride && (chunkstart+icswap+stride) < nblobs;
           ++icswap) {
        blob_minmax(blobs + chunkstart+icswap,
                    blobs + chunkstart+icswap+stride,
                    value_bytes);
      };
    };
  };
};

void pkpsig_sort_blob(struct pkpsig_sort_blob *blobs, size_t nblobs, size_t value_bytes) {
  const size_t n2 = 2*nblobs;
  int mergelen_l2;
  size_t mergelen, i;

  for (mergelen_l2 = 1, mergelen = 1 << mergelen_l2;
       mergelen < n2;
       ++mergelen_l2, mergelen += mergelen) {

    for (i = 0; i < nblobs; i += mergelen) {
      pkpsig_batcher_merge_blob(blobs + i, mergelen_l2, nblobs-i, value_bytes);
    };
  };
};

