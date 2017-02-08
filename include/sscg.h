/*
    This file is part of sscg.

    sscg is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sscg is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sscg.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017 by Stephen Gallagher <sgallagh@redhat.com>
*/

/* This is a master header file that should be included by all
   sscg source files. */

#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <talloc.h>

#ifndef _SSCG_H
# define _SSCG_H

/* TODO: implement internationalization */
#ifdef HAVE_GETTEXT
# define _(STRING) gettext (STRING)
#else
# define _(STRING) STRING
#endif /* HAVE_GETTEXT */

#ifndef EOK
# define EOK 0
#endif

#ifndef discard_const
# define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef talloc_zfree
#define talloc_zfree(ptr) do { talloc_free(discard_const(ptr)); ptr = NULL; } while(0)
#endif

#define CHECK_MEM(ptr) \
    do { \
        if (!ptr) { \
            ret = ENOMEM; \
            goto done; \
        } \
    } while(0)

#define CHECK_OK(_ret) \
    do { \
        if (_ret != EOK) { \
            goto done; \
        } \
    } while(0)

#define CHECK_SSL(_sslret, _fn) \
    do { \
        if (_sslret != 1) { \
            /* Get information about error from OpenSSL */ \
            fprintf(stderr, "Error occurred in " #_fn ": [%s].\n", \
                    ERR_error_string(ERR_get_error(), NULL)); \
            ret = EIO; \
            goto done; \
        } \
    } while(0)

enum sscg_verbosity {
    SSCG_QUIET = -1,
    SSCG_DEFAULT,
    SSCG_VERBOSE,
    SSCG_DEBUG
};

struct sscg_options {
    /* How noisy to be when printing information */
    enum sscg_verbosity verbosity;

    /* Whether to print the version and exit */
    bool print_version;

    /* How long should certificates be valid (in days) */
    short lifetime;

    /* Subject information */
    const char *country;
    const char *state;
    const char *locality;
    const char *org;
    const char *org_unit;
    const char *hostname;
    char **subject_alt_names;

    int key_strength;
    const EVP_MD *hash_fn;
};

#endif /* _SSCG_H */
