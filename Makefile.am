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

bin_PROGRAMS = sscg

sscg_SOURCES = \
    src/authority.c \
    include/authority.h \
    src/bignum.c \
    include/bignum.h \
    src/certificate.c \
    include/certificate.h \
    src/key.c \
    include/key.h \
    src/sscg.c \
    include/sscg.h

sscg_LDADD = \
    $(CRYPTO_LIBS) \
    $(POPT_LIBS) \
    $(TALLOC_LIBS) \
    $(NULL)
