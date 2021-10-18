
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
#include <unistd.h>

#include <pkpsig/api_unified.h>
#include <pkpsig/paramset.h>

#define FMT_TSV 0
#define FMT_CSV 1
#define FMT_HTML 2

static const char *headers[3] = {
  "paramset name\tpublic key bytes\tsecret key bytes\tsignature bytes\n",
  "paramset name,public key bytes,secret key bytes,signature bytes\r\n",
  "<html><head><title>PKPSIG parameter set table</title></head>\r\n"
  "<body><h1>PKPSIG parameter set table</h1>\r\n"
  "<table><tr><th>paramset name</th><th>public key bytes</th>"
  "<th>secret key bytes</th><th>signature bytes</th></tr>\r\n"
};

static const char *footers[3] = {
  "",
  "",
  "</table></body></html>\r\n"
};

static const char *linefmts[3] = {
  "%s\t%u\t%u\t%u\n",
  "%s,%u,%u,%u\r\n",
  "<tr><td>%s</td><td>%u</td><td>%u</td><td>%u</td></tr>\r\n"
};

static int paramset_enum_names_cb(void *ud, const char *name) {
  unsigned int pkbytes = pkpsig_simple_get_publickey_bytes(name);
  unsigned int skbytes = pkpsig_simple_get_secretkey_bytes(name);
  unsigned int sigbytes = pkpsig_simple_get_signature_bytes(name);

  printf(ud, name, pkbytes, skbytes, sigbytes);
  return 0;
};

static void usage(FILE *f) {
  fprintf(f, "usage: pkpsig-list-paramsets -tcH\n");
};

int main(int argc, char *argv[]) {
  int c, rv;
  int format = FMT_TSV;

  while ((c = getopt(argc, argv, "tcHh")) != -1) {
    switch (c) {
    case 't':
      format = FMT_TSV;
      break;
    case 'c':
      format = FMT_CSV;
      break;
    case 'H':
      format = FMT_HTML;
      break;
    case 'h':
      usage(stdout);
      return 0;
    default:
      usage(stderr);
      return 2;
    };
  };

  printf("%s", headers[format]);
  rv = pkpsig_paramset_enumerate_names(paramset_enum_names_cb,
                                       (void *)linefmts[format]);
  printf("%s", footers[format]);

  return rv;
};

