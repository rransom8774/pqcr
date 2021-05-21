#ifndef Xmmjj9cdeqxxbu00w0w04z0oh74k4xuyxg7fqm82u6rv4pus7m1ahlpm6rye2qv8j
#define Xmmjj9cdeqxxbu00w0w04z0oh74k4xuyxg7fqm82u6rv4pus7m1ahlpm6rye2qv8j

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

/* Signer/prover functions */

void pkpsig_zkpshamir_setup(struct pkpsig_sigstate *sst);
void pkpsig_zkpshamir_generate_commit1s(struct pkpsig_sigstate *sst);
void pkpsig_zkpshamir_generate_commit2s(struct pkpsig_sigstate *sst);

void pkpsig_zkpshamir_encode_proofs(struct pkpsig_sigstate *sst, uint8_t *outbuf);

/* Verifier functions */

void pkpsig_zkpshamir_decode_proofs(struct pkpsig_sigstate *sst, const uint8_t *inbuf);

void pkpsig_zkpshamir_regenerate_commits(struct pkpsig_sigstate *sst);

#endif
