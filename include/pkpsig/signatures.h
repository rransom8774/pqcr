#ifndef X8qmlpukocfyf7nabl305kdst4bfcbv73m12hxp27vmvsmfxu9r40rhus6g1roa56
#define X8qmlpukocfyf7nabl305kdst4bfcbv73m12hxp27vmvsmfxu9r40rhus6g1roa56

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

void pkpsig_signature_generate(struct pkpsig_sigstate *sst, uint8_t *sig, const uint8_t *msg, size_t msglen);
int pkpsig_signature_verify(struct pkpsig_sigstate *sst, const uint8_t *sig, const uint8_t *msg, size_t msglen);

#endif
