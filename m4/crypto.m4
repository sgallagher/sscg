AC_DEFUN([AM_CHECK_LIBCRYPTO],
         [PKG_CHECK_MODULES([CRYPTO],[libcrypto])
          AC_DEFINE_UNQUOTED(HAVE_LIBCRYPTO, 1, [Build with libcrypt crypto back end])
])
