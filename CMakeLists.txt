cmake_minimum_required(VERSION 3.12)
project(pqcr LANGUAGES C)

find_library(XKCP_LIBRARY XKCP)
find_library(OPENSSL_CRYPTO_LIBRARY crypto)

add_library(pqcr_djbsort STATIC
  src/djbsort/int32-portable4-sort.c
  src/djbsort/uint32-useint32-sort.c)
target_include_directories(pqcr_djbsort PUBLIC
  include/djbsort)

add_library(pqcr_common STATIC
  src/pqcr/modulo.c
  src/pqcr/vectenc.c)
target_include_directories(pqcr_common PRIVATE
  include/pqcr)
target_include_directories(pqcr_common INTERFACE
  include/pqcr
  include)

add_library(pqcr_pkpsig STATIC
  src/pkpsig/api_unified.c
  src/pkpsig/keys_core.c
  src/pkpsig/keys_generate.c
  src/pkpsig/keys_math.c
  src/pkpsig/keys_unpack.c
  src/pkpsig/paramset.c
  src/pkpsig/permute.c
  src/pkpsig/randombytes.c
  src/pkpsig/signatures.c
  src/pkpsig/sigstate.c
  src/pkpsig/sort_blob.c
  src/pkpsig/sort_int32.c
  src/pkpsig/symmetric_core.c
  src/pkpsig/zkpshamir.c)
target_link_libraries(pqcr_pkpsig PUBLIC
  pqcr_djbsort pqcr_common)
target_include_directories(pqcr_pkpsig PRIVATE
  include/pkpsig)
target_include_directories(pqcr_pkpsig INTERFACE
  include)

add_library(pqcr_pkpsig_openssl STATIC
  src/pkpsig/symmetric_shake_openssl.c)
target_link_libraries(pqcr_pkpsig_openssl PUBLIC
  pqcr_pkpsig crypto)
target_include_directories(pqcr_pkpsig_openssl PRIVATE
  include/pkpsig)

add_library(pqcr_pkpsig_xkcp STATIC
  src/pkpsig/symmetric_shake_xkcp.c)
target_link_libraries(pqcr_pkpsig_xkcp PUBLIC
  pqcr_pkpsig XKCP)
target_include_directories(pqcr_pkpsig_xkcp PRIVATE
  include/pkpsig)

add_library(pqcr_pkpsig_xoesch STATIC
  src/pkpsig/symmetric_xoesch256.c
  src/pkpsig/symmetric_xoesch384.c)
target_link_libraries(pqcr_pkpsig_xoesch PUBLIC
  pqcr_pkpsig pqcr_xoesch)
target_include_directories(pqcr_pkpsig_xoesch PRIVATE
  include/pkpsig)

add_library(pqcr_xoesch STATIC
  src/xoesch/xoesch.c)
target_include_directories(pqcr_xoesch PUBLIC
  include)

add_executable(generate-test-vectors
  src/test/generate-test-vectors.c
  src/test/randombytes_shake256_deterministic.c)
target_link_libraries(generate-test-vectors PUBLIC
  pqcr_pkpsig
  pqcr_pkpsig_xkcp pqcr_pkpsig_xoesch)

add_executable(generate-test-vectors-openssl
  src/test/generate-test-vectors.c
  src/test/randombytes_shake256_deterministic.c)
target_link_libraries(generate-test-vectors-openssl PUBLIC
  pqcr_pkpsig
  pqcr_pkpsig_openssl pqcr_pkpsig_xoesch
  XKCP)

add_executable(pkpsig-list-paramsets
  src/util/pkpsig-list-paramsets.c
  src/test/randombytes_shake256_deterministic.c)
target_link_libraries(pkpsig-list-paramsets PUBLIC
  pqcr_pkpsig
  pqcr_pkpsig_xkcp pqcr_pkpsig_xoesch)

