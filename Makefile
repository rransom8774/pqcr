
.DELETE_ON_ERROR:

.PHONY: test-bin build-dirs


CFLAGS = -g


CFLAGS_DJBSORT = -Iinclude/djbsort/ \
	${CFLAGS} \

CFLAGS_PQCR = -Iinclude/pqcr/ \
	-Iinclude/djbsort/ \
	${CFLAGS} \

CFLAGS_PKPSIG = -Iinclude/pkpsig/ \
	-Iinclude/pqcr/ \
	-Iinclude/djbsort/ \
	-Iinclude/ \
	${CFLAGS} \

CFLAGS_XOESCH = -Iinclude/ \
	${CFLAGS} \

CFLAGS_TEST = -Iinclude/ \
	-Iinclude/pqcr/ \
	${CFLAGS} \


LIBS_XKCP = -lXKCP \

LIBS_TEST_XKCP = ${LIBS_XKCP} \

LIBS_OPENSSL = -lcrypto \

LIBS_TEST_OPENSSL = ${LIBS_XKCP} \
	${LIBS_OPENSSL} \


LDFLAGS = -g

LDFLAGS_TEST_XKCP = ${LDFLAGS} ${LIBS_TEST_XKCP}

LDFLAGS_TEST_OPENSSL = ${LDFLAGS} ${LIBS_TEST_OPENSSL}


HEADERS_DJBSORT = \
	include/djbsort/int32_sort.h \
	include/djbsort/uint32_sort.h \

OBJS_DJBSORT = \
	out/djbsort/int32-portable4-sort.o \
	out/djbsort/uint32-useint32-sort.o \


HEADERS_PQCR = \
	include/pqcr/modulo.h \
	include/pqcr/vectenc.h \

OBJS_PQCR = \
	out/pqcr/modulo.o \
	out/pqcr/vectenc.o \


HEADERS_PKPSIG = \
	include/pkpsig/api_unified.h \
	include/pkpsig/keys.h \
	include/pkpsig/paramset.h \
	include/pkpsig/permute.h \
	include/pkpsig/randombytes.h \
	include/pkpsig/signatures.h \
	include/pkpsig/sigstate.h \
	include/pkpsig/sort.h \
	include/pkpsig/symmetric.h \
	include/pkpsig/zkpshamir.h \

OBJS_PKPSIG = \
	out/pkpsig/api_unified.o \
	out/pkpsig/keys_core.o \
	out/pkpsig/keys_generate.o \
	out/pkpsig/keys_math.o \
	out/pkpsig/keys_unpack.o \
	out/pkpsig/paramset.o \
	out/pkpsig/permute.o \
	out/pkpsig/randombytes.o \
	out/pkpsig/signatures.o \
	out/pkpsig/sigstate.o \
	out/pkpsig/sort_blob.o \
	out/pkpsig/sort_int32.o \
	out/pkpsig/symmetric_core.o \
	out/pkpsig/symmetric_xoesch256.o \
	out/pkpsig/symmetric_xoesch384.o \
	out/pkpsig/zkpshamir.o \

OBJS_PKPSIG_XKCP = \
	out/pkpsig/symmetric_shake_xkcp.o \

OBJS_PKPSIG_OPENSSL = \
	out/pkpsig/symmetric_shake_openssl.o \


HEADERS_XOESCH = \
	include/xoesch/xoesch.h \

OBJS_XOESCH = \
	out/xoesch/xoesch.o \


HEADERS_LIB = \
	$(HEADERS_DJBSORT) \
	$(HEADERS_PQCR) \
	$(HEADERS_PKPSIG) \
	$(HEADERS_XOESCH) \

OBJS_LIB = \
	$(OBJS_DJBSORT) \
	$(OBJS_PQCR) \
	$(OBJS_PKPSIG) \
	$(OBJS_XOESCH) \

OBJS_LIB_XKCP = \
	$(OBJS_LIB) \
	$(OBJS_PKPSIG_XKCP) \

OBJS_LIB_OPENSSL = \
	$(OBJS_LIB) \
	$(OBJS_PKPSIG_OPENSSL) \


HEADERS_GEN_TEST_VECS = \
	src/test/randombytes_shake256_deterministic.h \

OBJS_GEN_TEST_VECS = \
	out/test/generate-test-vectors.o \
	out/test/randombytes_shake256_deterministic.o \


TESTPROGS = \
	out/test/generate-test-vectors \
	out/test/generate-test-vectors-openssl \


test-bin: build-dirs $(TESTPROGS)


build-dirs:
	mkdir -p out out/djbsort out/pkpsig out/pqcr out/test out/xoesch


out/test/generate-test-vectors: $(OBJS_GEN_TEST_VECS) $(OBJS_LIB_XKCP)
	$(CC) -o $@ $+ $(LDFLAGS_TEST_XKCP)

out/test/generate-test-vectors-openssl: $(OBJS_GEN_TEST_VECS) $(OBJS_LIB_OPENSSL)
	$(CC) -o $@ $+ $(LDFLAGS_TEST_OPENSSL)

out/test/randombytes_shake256_deterministic.o: src/test/randombytes_shake256_deterministic.c $(HEADERS_GEN_TEST_VECS)
	$(CC) -c -o $@ $(CFLAGS_TEST) $<

out/test/generate-test-vectors.o: src/test/generate-test-vectors.c $(HEADERS_GEN_TEST_VECS) $(HEADERS_LIB)
	$(CC) -c -o $@ $(CFLAGS_TEST) $<


out/djbsort/int32-portable4-sort.o: src/djbsort/int32-portable4-sort.c $(HEADERS_DJBSORT)
	cc -c -o $@ $< $(CFLAGS_DJBSORT)

out/djbsort/uint32-useint32-sort.o: src/djbsort/uint32-useint32-sort.c $(HEADERS_DJBSORT)
	cc -c -o $@ $< $(CFLAGS_DJBSORT)


out/pqcr/modulo.o: src/pqcr/modulo.c $(HEADERS_PQCR)
	cc -c -o $@ $< $(CFLAGS_PQCR)

out/pqcr/vectenc.o: src/pqcr/vectenc.c $(HEADERS_PQCR)
	cc -c -o $@ $< $(CFLAGS_PQCR)


out/pkpsig/api_unified.o: src/pkpsig/api_unified.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/keys_core.o: src/pkpsig/keys_core.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/keys_generate.o: src/pkpsig/keys_generate.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/keys_math.o: src/pkpsig/keys_math.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/keys_unpack.o: src/pkpsig/keys_unpack.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/paramset.o: src/pkpsig/paramset.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/permute.o: src/pkpsig/permute.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/randombytes.o: src/pkpsig/randombytes.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/signatures.o: src/pkpsig/signatures.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/sigstate.o: src/pkpsig/sigstate.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/sort_blob.o: src/pkpsig/sort_blob.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/sort_int32.o: src/pkpsig/sort_int32.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/symmetric_core.o: src/pkpsig/symmetric_core.c src/pkpsig/symmetric_internal.h src/pkpsig/symmetric_endian.h $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/symmetric_shake_xkcp.o: src/pkpsig/symmetric_shake_xkcp.c src/pkpsig/symmetric_internal.h src/pkpsig/symmetric_endian.h $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/symmetric_shake_openssl.o: src/pkpsig/symmetric_shake_openssl.c src/pkpsig/symmetric_internal.h src/pkpsig/symmetric_endian.h $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/symmetric_xoesch256.o: src/pkpsig/symmetric_xoesch256.c src/pkpsig/symmetric_internal.h src/pkpsig/symmetric_endian.h $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/symmetric_xoesch384.o: src/pkpsig/symmetric_xoesch384.c src/pkpsig/symmetric_internal.h src/pkpsig/symmetric_endian.h $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)

out/pkpsig/zkpshamir.o: src/pkpsig/zkpshamir.c $(HEADERS_PKPSIG)
	cc -c -o $@ $< $(CFLAGS_PKPSIG)


out/xoesch/xoesch.o: src/xoesch/xoesch.c $(HEADERS_XOESCH)
	cc -c -o $@ $< $(CFLAGS_XOESCH)

