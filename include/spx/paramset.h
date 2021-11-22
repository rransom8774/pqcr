#ifndef Xycvlro6qzh2z84dnc7hifgrn2xlhxrpxsg7okzxmwjmgv2qm9w8whwyt6ipyhoa2
#define Xycvlro6qzh2z84dnc7hifgrn2xlhxrpxsg7okzxmwjmgv2qm9w8whwyt6ipyhoa2

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

struct spx_paramset {
  char *name;
  uint16_t hash_bytes; /* n */
  uint16_t hypertree_height; /* h */
  uint16_t hypertree_depth; /* d */
  uint16_t fors_leaves; /* log(t), lt */
  uint16_t fors_trees; /* k */
  uint16_t winternitz_base; /* w */
};

struct spx_paramset *spx_paramset_alloc_by_name(const char *name);
void spx_paramset_free(struct spx_paramset *ps);



#endif
