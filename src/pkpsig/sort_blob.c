
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

/* Given two sorted subsequences, one at indices from 0 to nfirstrun-1
 * and one at indices from nfirstrun to nblobs-1, merge them into a
 * single sorted sequence. */
void pkpsig_merge_runs_blob(struct pkpsig_sort_blob *blobs, size_t nfirstrun, size_t nblobs, size_t value_bytes) {
  int mergelen_l2 = 1;
  size_t mergelen = ((size_t) 1) << mergelen_l2,
         mergemask = mergelen - 1,
         chunkstart = nfirstrun & ~mergemask;

  while ((chunkstart != 0) || (mergelen < nblobs)) {
    if (chunkstart != nfirstrun) {
      pkpsig_batcher_merge_blob(blobs + chunkstart, mergelen_l2, nblobs - chunkstart, value_bytes);
    };

    /* increment mergelen_l2 and set all derived vars accordingly */
    ++mergelen_l2; mergelen += mergelen;
    mergemask += mergemask + 1; chunkstart = nfirstrun & ~mergemask;
  };

  pkpsig_batcher_merge_blob(blobs, mergelen_l2, nblobs, value_bytes);
};

void pkpsig_sort_pairs_blob(struct pkpsig_sort_blob *blobs, size_t nblobs, size_t value_bytes) {
  size_t i;

  nblobs &= ~(size_t) 1;

  for (i = 0; i < nblobs; i += 2) {
    pkpsig_batcher_merge_blob(blobs + i, 1, nblobs - i, value_bytes);
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

