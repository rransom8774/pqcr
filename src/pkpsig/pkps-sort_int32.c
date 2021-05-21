
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include "sort.h"

/* djbsort includes */
#include <uint32_sort.h>
#include <int32_sort.h>

#ifdef DEBUG_CHECK_SORT
#include <assert.h>
#endif

/* The padding functions exist because the avx2 implementation of
   djbsort copies inputs of non-power-of-2 length between 8 and 256 to
   pad them to the next power of 2, whereas the portable versions
   never pad their input and will be slowed down by a pre-padded
   array.

   Ideally this file should select the best available sort
   implementation for the current system at initialization, and
   recommend appropriate padding sizes for the implementation in
   use. */

/* Padding policy function for avx2 djbsort. */
size_t pkpsig_sort_anyint32_get_pad_length(size_t veclen) {
  size_t rv;

  if ((veclen <= 8) || (veclen >= 256)) {
    return veclen;
  };

  rv = 16;
  while (rv < veclen) rv += rv;

  return rv;
};

/* Generic functions to fill in the padding with a maximal element. */
size_t pkpsig_sort_uint32_pad_sortbuf(uint32_t *buf, size_t veclen) {
  size_t padlen = pkpsig_sort_anyint32_get_pad_length(veclen);
  size_t i;

  for (i = veclen; i < padlen; ++i) buf[i] = 0xFFFFFFFF;

  return padlen;
};

size_t pkpsig_sort_posint32_pad_sortbuf(uint32_t *buf, size_t veclen) {
  size_t padlen = pkpsig_sort_anyint32_get_pad_length(veclen);
  size_t i;

  for (i = veclen; i < padlen; ++i) buf[i] = 0x7FFFFFFF;

  return padlen;
};

void pkpsig_sort_uint32(uint32_t *buf, size_t padlen) {
#ifdef DEBUG_CHECK_SORT
  size_t i;
#endif

  uint32_sort(buf, padlen);

#ifdef DEBUG_CHECK_SORT
  for (i = 1; i < padlen; ++i) {
    assert(buf[i-1] <= buf[i]);
  };
#endif
};

/* Sorting function for inputs which are within the range of positive
   signed integers, and can thus be compared and sorted correctly
   using whichever of int32 or uint32 has a faster implementation.  In
   the current (avx2 and portable[34]) implementations of djbsort,
   int32 is faster. */
void pkpsig_sort_posint32(uint32_t *buf, size_t padlen) {
#ifdef DEBUG_CHECK_SORT
  size_t i;

  for (i = 0; i < padlen; ++i) {
    assert((buf[i] & 0x80000000) == 0);
  };
#endif

  int32_sort((int32_t *)buf, padlen);

#ifdef DEBUG_CHECK_SORT
  for (i = 1; i < padlen; ++i) {
    assert(buf[i-1] <= buf[i]);
  };
#endif
};

