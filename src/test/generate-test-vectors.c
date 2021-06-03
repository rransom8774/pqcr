
/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkpsig/api_common.h>
#include <pkpsig/api_unified.h>
#include <pkpsig/paramset.h>

#include "randombytes_shake256_deterministic.h"

#include <XKCP/KeccakSponge.h>

#include <sys/stat.h>
#include <sys/types.h>

static inline void pack_ui32(uint8_t *buf, uint32_t x) {
  buf[0] =  x        & 255;
  buf[1] = (x >>  8) & 255;
  buf[2] = (x >> 16) & 255;
  buf[3] = (x >> 24) & 255;
};

struct buffer {
  uint8_t *data;
  size_t len;
  size_t capacity;
};
#define BUFFER_STATIC_INIT {NULL, 0, 0}

static int buffer_resize(struct buffer *buf, size_t newlen) {
  if (buf->capacity < newlen) {
    uint8_t *newptr = realloc(buf->data, newlen);
    if (newptr == NULL) return -1;

    buf->data = newptr;
    buf->capacity = newlen;
  };

  /* now buf->capacity >= newlen */
  buf->len = newlen;
  return 0;
};
#define BUFFER_RESIZE(buf, newlen) buffer_resize(&(buf), (newlen))

static struct buffer fnamebuf = BUFFER_STATIC_INIT;

static struct buffer pubkeybuf = BUFFER_STATIC_INIT;
static struct buffer seckeybuf = BUFFER_STATIC_INIT;
static struct buffer msgbuf = BUFFER_STATIC_INIT;
static struct buffer sigbuf = BUFFER_STATIC_INIT;

static int init_test_buffers(const char *psname, uint32_t count) {
  int rv = 0;

  rv |= BUFFER_RESIZE(pubkeybuf, pkpsig_simple_get_publickey_bytes(psname));
  rv |= BUFFER_RESIZE(seckeybuf, pkpsig_simple_get_secretkey_bytes(psname));
  rv |= BUFFER_RESIZE(msgbuf, 33 * (size_t)count);
  rv |= BUFFER_RESIZE(sigbuf, pkpsig_simple_get_signature_bytes(psname));

  if (rv != 0) {
    fprintf(stderr, "data buffer allocation failed\n");
    return -1;
  };
};

static int compute_test_vector(const char *psname, uint32_t i) {
  uint8_t buf[4];
  int rv;
  size_t msglen = 33 * (size_t)i;

  pack_ui32(buf, i);
  randombytes_shake256_det_init(buf, 4);

  /* FIXME does not reinitialize buffer sizes */     

  rv = BUFFER_RESIZE(msgbuf, msglen);
  if (rv != 0) {
    fprintf(stderr, "message buffer resize failed\n");
    return -1;
  };

  rv = randombytes(msgbuf.data, msgbuf.len);
  if (rv != 0) {
    fprintf(stderr, "message buffer initialization (randombytes) failed (%i)\n", rv);
    return -1;
  };

  rv = pkpsig_simple_keypair(psname, pubkeybuf.data, seckeybuf.data);
  if (rv != 0) {
    fprintf(stderr, "keypair generation failed (%i)\n", rv);
    return -1;
  };

  rv = pkpsig_simple_detached_sign(psname, sigbuf.data, msgbuf.data, msgbuf.len, seckeybuf.data);
  if (rv != 0) {
    fprintf(stderr, "signature generation failed (%i)\n", rv);
    return -1;
  };

  rv = pkpsig_simple_detached_verify(psname, sigbuf.data, msgbuf.data, msgbuf.len, pubkeybuf.data);
  if (rv != 0) {
    fprintf(stderr, "signature verification failed (%i)\n", rv);
    return -1;
  };
};

static void write_ui32(FILE *f, uint32_t i) {
  uint8_t buf[4];
  pack_ui32(buf, i);
  fwrite(buf, 4, 1, f);
};

static int write_size_ui32(FILE *f, size_t i) {
  if (i != (size_t)(i & 0xFFFFFFFFUL)) {
    fprintf(stderr, "size too large\n");
    return -1;
  };

  write_ui32(f, (uint32_t)i);

  return 0;
};

static int write_buf(FILE *f, struct buffer *pbuf) {
  int rv1 = write_size_ui32(f, pbuf->len);
  int rv2 = fwrite(pbuf->data, pbuf->len, 1, f);

  if ((rv1 | rv2) < 0) return -1;
  return 0;
};

static int generate_test_vector_file(const char *psname, uint32_t i) {
  ssize_t fname_len;
  FILE *f = NULL;
  int rv = 0;

  rv = init_test_buffers(psname, i);
  if (rv < 0) return rv;

  while (1) {
    fname_len = snprintf(fnamebuf.data, fnamebuf.capacity,
                         "out/testvecs/%s/testvec-%s-%lu.bin",
                         "pkpsig", psname, (unsigned long)i);
    if (fname_len + 1 <= fnamebuf.capacity) {
      fnamebuf.data[fname_len] = '\0';
      fnamebuf.len = fname_len + 1;
      break;
    };
    rv = BUFFER_RESIZE(fnamebuf, fname_len + 1);
    if (rv < 0) {
      fprintf(stderr, "filename buffer allocation failed\n");
      return rv;
    };
  };

  f = fopen(fnamebuf.data, "wb");
  if (f == NULL) {
    fprintf(stderr, "error opening output file %s\n", fnamebuf.data);
    return -1;
  };

  write_ui32(f, i);

  rv = compute_test_vector(psname, i);
  if (rv < 0) {
    fprintf(stderr, "error generating test vector %s\n", fnamebuf.data);
    goto end;
  };

  write_buf(f, &seckeybuf);
  write_buf(f, &pubkeybuf);
  write_buf(f, &msgbuf);
  write_buf(f, &sigbuf);

  if (ferror(f) != 0) {
    fprintf(stderr, "error writing test vector %s\n", fnamebuf.data);
    rv = -1;
  };

 end:
  if (fclose(f) != 0) {
    fprintf(stderr, "error closing test vector file %s\n", fnamebuf.data);
    rv = -1;
  };
  return rv;
};

static int enum_names_cb(void *ud, const char *name) {
  uint32_t *pcount = ud;
  uint32_t i;

  printf("%s\n", name);

  for (i = 0; i < *pcount; ++i) {
    if (generate_test_vector_file(name, i) < 0) {
      return 1;
    };
  };

  return 0;
};

int main(int argc, char *argv[]) {
  uint32_t count = 10;  /* FIXME allow user to specify count */   
  uint32_t i;
  const char *paramset_name = NULL;

  switch (argc) {
  case 2:
    paramset_name = argv[1];
    /* fall through */
  case 1:
    break;
  case 0:
  default:
    fprintf(stderr, "usage: generate-test-vectors PARAMSET-NAME\n");
    return 2;
  };

  pkpsig_init();

  /* mode 0777: rely on the user's umask for consistency with other programs */
  mkdir("out", 0777);
  mkdir("out/testvecs", 0777);
  mkdir("out/testvecs/pkpsig", 0777);

  if (paramset_name == NULL) {
    pkpsig_paramset_enumerate_names(enum_names_cb, &count);
  } else {
    for (i = 0; i < count; ++i) {
      if (generate_test_vector_file(paramset_name, i) < 0) {
        return 1;
      };
    };
  };

  return 0;
};

