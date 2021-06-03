
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

/* XXX These should be replaced with target-specific versions. */

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

static inline void pack_ui16(uint8_t *buf, uint16_t x) {
  buf[0] =  x        & 255;
  buf[1] = (x >>  8) & 255;
};

static inline void pack_ui16vec(uint8_t *buf, const uint16_t *v, size_t n) {
  size_t i;

  for (i = 0; i < n; ++i) {
    pack_ui16(buf + (i*2), v[i]);
  };
};

