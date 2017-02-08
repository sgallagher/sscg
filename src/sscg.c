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

#include <popt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "config.h"
#include "include/sscg.h"
#include "include/authority.h"

static int
set_default_options(struct sscg_options *opts)
{

    opts->lifetime = 3650;
    opts->key_strength = 2048;
    return 0;
}

static void
print_options(struct sscg_options *opts)
{
    size_t i = 0;
    fprintf(stdout, "==== Options ====\n");
    fprintf(stdout, "Certificate lifetime: %d\n", opts->lifetime);
    fprintf(stdout, "Country: \"%s\"\n", opts->country);
    fprintf(stdout, "State or Principality: \"%s\"\n", opts->state);
    fprintf(stdout, "Locality: \"%s\"\n", opts->locality);
    fprintf(stdout, "Organization: \"%s\"\n", opts->org);
    fprintf(stdout, "Organizational Unit: \"%s\"\n", opts->org_unit);
    fprintf(stdout, "Hostname: \"%s\"\n", opts->hostname);
    if (opts->subject_alt_names) {
        for (i = 0; opts->subject_alt_names[i]; i++) {
            fprintf(stdout, "Subject Alternative Name: \"%s\"\n",
                    opts->subject_alt_names[i]);
        }
    }
    fprintf(stdout, "=================\n");
}

int
main(int argc, const char **argv)
{
    int ret, sret, opt;
    size_t i;
    poptContext pc;
    struct sscg_options *options;

    char *country = NULL;
    char *state = NULL;
    char *locality = NULL;
    char *organization = NULL;
    char *organizational_unit = NULL;
    char *hostname = NULL;
    char *hash_alg = NULL;
    char **alternative_names = NULL;

    struct sscg_x509_cert *cacert;

    TALLOC_CTX *main_ctx = talloc_new(NULL);
    if (!main_ctx) {
        fprintf(stderr, "Could not allocate memory.");
        return ENOMEM;
    }

    options = talloc_zero(main_ctx, struct sscg_options);
    CHECK_MEM(options);

    ret = set_default_options(options);
    if (ret != EOK) goto done;

    options->verbosity = SSCG_DEFAULT;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"quiet", 'q', POPT_ARG_VAL, &options->verbosity, SSCG_QUIET,
         _("Display no output unless there is an error."), NULL },
        {"verbose", 'v', POPT_ARG_VAL, &options->verbosity, SSCG_VERBOSE,
         _("Display progress messages."), NULL },
        {"debug", 'd', POPT_ARG_VAL, &options->verbosity, SSCG_DEBUG,
         _("Enable logging of debug messages. Implies verbose. Warning! "
           "This will print private key information to the screen!"), NULL},
        {"version", 'V', POPT_ARG_NONE, &options->print_version, 0,
         _("Display the version number and exit."), NULL},
        {"lifetime", '\0', POPT_ARG_INT|POPT_ARGFLAG_SHOW_DEFAULT, &options->lifetime, 3650,
         _("Certificate lifetime (days)."),
         _("1-3650")},
        {"country", '\0', POPT_ARG_STRING, &country, 0,
         _("Certificate DN: Country (C). (default: \"US\")"),
         _("US, CZ, etc.")},
        {"state", '\0', POPT_ARG_STRING, &state, 0,
         _("Certificate DN: State or Province (ST)."),
         _("Massachusetts, British Columbia, etc.")},
        {"locality", '\0', POPT_ARG_STRING, &locality, 0,
         _("Certificate DN: Locality (L)."),
         _("Westford, Paris, etc.")},
        {"organization", '\0', POPT_ARG_STRING, &organization, 0,
         _("Certificate DN: Organization (O). (default: \"Unspecified\")"),
         _("My Company")},
        {"organizational-unit", '\0', POPT_ARG_STRING, &organizational_unit, 0,
         _("Certificate DN: Organizational Unit (OU)."),
         _("Engineering, etc.")},
        {"hostname", '\0', POPT_ARG_STRING, &hostname, 0,
         _("The valid hostname of the certificate. Must be an FQDN. (default: current system FQDN)"),
         _("server.example.com")},
        {"subject-alt-name", '\0', POPT_ARG_ARGV, &alternative_names, 0,
         _("Optional additional valid hostnames for the certificate. "
           "May be specified multiple times."),
         _("alt.example.com")},
        {"key-strength", '\0', POPT_ARG_INT|POPT_ARGFLAG_SHOW_DEFAULT, &options->key_strength, 0,
         _("Strength of the certificate private keys in bits."),
         _("{512,1024,2048,4096}")},
        {"hash-alg", '\0', POPT_ARG_STRING, &hash_alg, 0,
         _("Hashing algorithm to use for signing. (default: sha256)"),
         _("{sha256,sha384,sha512}"),
        },
        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    if (options->print_version) {
        /* Print the version number and exit */
        printf("%s\n", PACKAGE_VERSION);
        return 0;
    }

    /* Process the Subject information */

    if (country) {
        if (strlen(country) != 2) {
            fprintf(stderr, "Country codes must be exactly two letters.\n");
            ret = EINVAL;
            goto done;
        }
        options->country = talloc_strdup(options, country);
    } else {
        /* Country name is mandatory. 1.0 (in Golang) defaulted to
           "US", so we'll keep it the same to avoid breaking existing
           usages. */
        options->country = talloc_strdup(options, "US");
    }
    CHECK_MEM(options->country);

    if (state) {
        options->state = talloc_strdup(options, state);
    } else {
        options->state = talloc_strdup(options, "");
    }
    CHECK_MEM(options->state);

    if (locality) {
        options->locality = talloc_strdup(options, locality);
    } else {
        options->locality = talloc_strdup(options, "");
    }
    CHECK_MEM(options->locality);

    if (organization) {
        options->org = talloc_strdup(options, organization);
    } else {
        /* In 1.0 (Golang), organization defaulted to "Unspecified".
           Keep it the same here to avoid breaking existing usages. */
        options->org = talloc_strdup(options, "Unspecified");
    }
    CHECK_MEM(options->org);

    if (organizational_unit) {
        options->org_unit = talloc_strdup(options, organizational_unit);
    } else {
        options->org_unit = talloc_strdup(options, "");
    }
    CHECK_MEM(options->org_unit);

    if (hostname) {
        options->hostname = talloc_strdup(options, hostname);
    } else {
        /* Get hostname from the system */
        hostname = talloc_zero_array(options, char, HOST_NAME_MAX+1);
        CHECK_MEM(hostname);

        sret = gethostname(hostname, HOST_NAME_MAX);
        if (sret != 0) {
            ret = errno;
            goto done;
        }

        options->hostname = hostname;
    }
    CHECK_MEM(options->hostname);

    /* Use a realloc loop to copy the names from popt into the
       options struct. It's not the most efficient approach, but
       it's only done one time, so there is no sense in optimizing
       it. */
    if (alternative_names) {
        i = 0;
        while (alternative_names[i] != NULL) {
            options->subject_alt_names =
                talloc_realloc(options, options->subject_alt_names,
                               char *, i + 2);
            CHECK_MEM(options->subject_alt_names);

            options->subject_alt_names[i] =
                talloc_strdup(options->subject_alt_names, alternative_names[i]);
            CHECK_MEM(options->subject_alt_names[i]);

            /* Add a NULL terminator to the end */
            options->subject_alt_names[i + 1] = NULL;
            i++;
        }
    }

    if (options->key_strength != 512
        && options->key_strength != 1024
        && options->key_strength != 2048
        && options->key_strength != 4096) {

        fprintf(stderr, "Key strength must be one of {512, 1024, 2048, 4096}.\n");
        ret = EINVAL;
        goto done;
    }

    if (!hash_alg) {
        /* Default to SHA256 */
        options->hash_fn = EVP_sha256();
    } else {
        /* TODO: restrict this to approved hashes.
         * For now, we'll only list SHA[256|384|512] in the help */
        options->hash_fn = EVP_get_digestbyname(hash_alg);
    }
    if (!options->hash_fn) {
        fprintf(stderr, "Unsupported hashing algorithm.");
    }

    /* On verbose logging, display all of the selected options. */
    if (options->verbosity >= SSCG_VERBOSE) print_options(options);

    poptFreeContext(pc);

    ret = create_private_CA(main_ctx, options, &cacert);
    CHECK_OK(ret);


done:
    talloc_zfree(main_ctx);
    if (ret != EOK) {
        fprintf(stderr, "%s\n", strerror(ret));
    }
    return ret;
}
