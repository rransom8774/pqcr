
#include "paramset.h"

#include <stdlib.h>
#include <string.h>

struct name_map_entry {
  const char *published_name;
  const char *canonical_name;
};
static struct name_map_entry name_map[] = {
  {"128s",        "n16h63d7w16lt12k14"},
  {"128s-round3", "n16h63d7w16lt12k14"},
  {"128f",        "n16h66d22w16lt6k33"},
  {"128f-round3", "n16h66d22w16lt6k33"},
  {"192s",        "n24h63d7w16lt14k17"},
  {"192s-round3", "n24h63d7w16lt14k17"},
  {"192f",        "n24h66d22w16lt8k33"},
  {"192f-round3", "n24h66d22w16lt8k33"},
  {"256s",        "n32h64d8w16lt14k22"},
  {"256s-round3", "n32h64d8w16lt14k22"},
  {"256f",        "n32h68d17w16lt9k35"},
  {"256f-round3", "n32h68d17w16lt9k35"},
  {"128s-round1", "n16h64d8w16lt15k10"},
  {"128f-round1", "n16h60d20w16lt9k30"},
  {"192s-round1", "n24h64d8w16lt16k14"},
  {"192f-round1", "n24h66d22w16lt8k33"},
  {"256s-round1", "n32h64d8w16lt14k22"},
  {"256f-round1", "n32h68d17w16lt10k30"},
};
#define N_NAME_MAP_ENTRIES (sizeof(name_map)/sizeof(name_map[0]))

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
  size_t name_len, i;

  if (ps == NULL) return NULL;

  for (i = 0; i < N_NAME_MAP_ENTRIES; ++i) {
    if (strcmp(name, name_map[i].published_name) == 0) {
      name = name_map[i].canonical_name;
      break;
    };
  };

  ps->hash_bytes = scan_param_uint16(&inptr, &errflag, "n", 16, 32);
  ps->hypertree_height = scan_param_uint16(&inptr, &errflag, "h", 48, 256);
  ps->hypertree_depth = scan_param_uint16(&inptr, &errflag, "d", 4, 64);
  ps->winternitz_base = scan_param_uint16(&inptr, &errflag, "w", 2, 256);
  ps->fors_leaves = scan_param_uint16(&inptr, &errflag, "lt", 4, 64);
  ps->fors_trees = scan_param_uint16(&inptr, &errflag, "k", 8, 64);

  name_len = snprintf(name_buf, sizeof(name_buf), "n%uih%uid%uiw%uilt%uik%ui",
                      ps->hash_bytes,
                      ps->hypertree_height, ps->hypertree_depth,
                      ps->winternitz_base,
                      ps->fors_leaves, ps->fors_trees);
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

