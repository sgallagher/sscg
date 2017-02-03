CLEANFILES = $(NULL)
BUILT_SOURCES = $(NULL)

AM_CFLAGS =
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
                 -Wcast-qual -Wcast-align -Wwrite-strings -Wundef \
                 -Werror-implicit-function-declaration -Winit-self \
                 -Wmissing-include-dirs \
                 -fno-strict-aliasing \
                 -std=gnu99
endif

AM_CPPFLAGS = \
   -Wall \
   -I. \
   $(CRYPTO_CFLAGS) \
   $(POPT_CFLAGS) \
   $(TALLOC_CFLAGS) \
   -DLIBDIR=\"$(libdir)\" \
   -DVARDIR=\"$(localstatedir)\" \
   $(NULL)

COMMON_LIBS = \
    $(CRYPTO_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    libsscg.la

bin_PROGRAMS = sscg

noinst_LTLIBRARIES = libsscg.la

TESTS = \
    create_csr_test \
    generate_rsa_key_test \
    generate_serial_test \
    init_bignum_test

check_PROGRAMS = \
    $(TESTS)

sscg_SOURCES = \
    src/sscg.c \
    include/sscg.h

libsscg_la_SOURCES = \
    src/authority.c \
    include/authority.h \
    src/bignum.c \
    include/bignum.h \
    src/key.c \
    include/key.h \
    src/x509.c \
    include/x509.h

sscg_LDADD = \
    $(COMMON_LIBS) \
    $(NULL)

init_bignum_test_SOURCES = \
    test/init_bignum_test.c

init_bignum_test_LDADD = \
    $(COMMON_LIBS) \
    $(NULL)

generate_serial_test_SOURCES = \
    test/generate_serial_test.c

generate_serial_test_LDADD = \
    $(COMMON_LIBS) \
    $(NULL)

generate_rsa_key_test_SOURCES = \
    test/generate_rsa_key_test.c

generate_rsa_key_test_LDADD = \
    $(COMMON_LIBS) \
    $(NULL)

create_csr_test_SOURCES = \
    test/create_csr_test.c

create_csr_test_LDADD = \
    $(COMMON_LIBS) \
    $(NULL)
