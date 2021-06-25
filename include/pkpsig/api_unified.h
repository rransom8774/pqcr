#ifndef X5871q3t4ammlqzyvc5gnq2bhitb55rygqfq2b053iuq4wruudptql03nkndusg9g
#define X5871q3t4ammlqzyvc5gnq2bhitb55rygqfq2b053iuq4wruudptql03nkndusg9g

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

#include <sys/types.h>

ssize_t pkpsig_simple_get_publickey_bytes(const char *paramset_name);
ssize_t pkpsig_simple_get_secretkey_bytes(const char *paramset_name);
ssize_t pkpsig_simple_get_signature_bytes(const char *paramset_name);

int pkpsig_simple_keypair(const char *paramset_name, uint8_t *publickey_out, uint8_t *secretkey_out);
int pkpsig_simple_secretkey_to_publickey(const char *paramset_name, uint8_t *publickey_out, const uint8_t *secretkey);

int pkpsig_simple_detached_sign(const char *paramset_name, uint8_t *sigout, const uint8_t *msg, size_t msglen, const uint8_t *secretkey);

int pkpsig_simple_detached_verify(const char *paramset_name, const uint8_t *sigin, const uint8_t *msg, size_t msglen, const uint8_t *publickey);

int pkpsig_simple_supercop_sign(const char *paramset_name, uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *secretkey);

int pkpsig_simple_supercop_sign_open(const char *paramset_name, uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *publickey);

#endif
