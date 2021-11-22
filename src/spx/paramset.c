
#include "paramset.h"

#include <stdlib.h>
#include <string.h>

static uint16_t scan_param_uint16(const char **pbufptr, int *errflag, const char *leading_chars, uint16_t lbound, uint16_t ubound) {
  unsigned long long rv;
  size_t n_leading_chars = strlen(leading_chars);

  if (errflag) goto err;

  if (memcmp(*pbufptr, leading_chars, n_leading_chars) == 0) {
    (*pbufptr) += n_leading_chars;
  } else {
    goto err;
  };

  if ((**pbufptr < '0') || (**pbufptr > '9')) {
    goto err;
  };

  rv = strtoull(*pbufptr, pbufptr, 10);
  if ((rv < lbound) || (rv > ubound)) {
    goto err;
  };

  return rv;

 err:
  *errflag = 1;
  return 0;
};

struct spx_paramset *spx_paramset_alloc_by_name(const char *name) {
  struct spx_paramset *ps = calloc(1, sizeof(struct spx_paramset));
  const char *inptr = name;
  int errflag = 0;
  char name_buf[128];
  size_t name_len;

  if (ps == NULL) return NULL;

  ps->hash_bytes = scan_param_uint16(&inptr, &errflag, "n", 16, 32);
  ps->hypertree_height = scan_param_uint16(&inptr, &errflag, "h", 48, 256);
  ps->hypertree_depth = scan_param_uint16(&inptr, &errflag, "d", 4, 64);
  ps->fors_leaves = scan_param_uint16(&inptr, &errflag, "lt", 4, 64);
  ps->fors_trees = scan_param_uint16(&inptr, &errflag, "k", 8, 64);
  ps->winternitz_base = scan_param_uint16(&inptr, &errflag, "w", 2, 256);

  name_len = snprintf(name_buf, sizeof(name_buf), "n%uih%uid%uilt%uik%uiw%ui",
                      ps->hash_bytes, ps->hypertree_height, ps->hypertree_depth,
                      ps->fors_leaves, ps->fors_trees, ps->winternitz_base);
  if (name_len > sizeof(name_buf) - 1) goto err;
  if (strcmp(name, name_buf) != 0) goto err;
  ps->name = strdup(name_buf);
  if (ps->name == NULL) goto err;

  return ps;

 err:
  spx_paramset_free(ps);
  return NULL;
};

void spx_paramset_free(struct spx_paramset *ps) {
  if (ps == NULL) return;
  if (ps->name != NULL) {
    free(ps->name);
    ps->name = NULL;
  };
  free(ps);
};

