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

#include <stdlib.h>
#include <stdio.h>
#include <talloc.h>
#include <popt.h>

#include "config.h"
#include "include/sscg.h"

int
main(int argc, const char **argv)
{
    int opt;
    poptContext pc;
    struct sscg_options *options;

    TALLOC_CTX *main_ctx = talloc_new(NULL);
    if (!main_ctx) {
        fprintf(stderr, "Could not allocate memory.");
        return 1;
    }

    options = talloc_zero(main_ctx, struct sscg_options);
    if (!main_ctx) {
        fprintf(stderr, "Could not allocate memory.");
        return 1;
    }

    options->verbosity = SSCG_DEFAULT;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"quiet", 'q', POPT_ARG_VAL, &options->verbosity, SSCG_QUIET,
         _("Display no output unless there is an error."), NULL }, \
        {"verbose", 'v', POPT_ARG_VAL, &options->verbosity, SSCG_VERBOSE,
         _("Display progress messages."), NULL }, \
        {"debug", 'd', POPT_ARG_VAL, &options->verbosity, SSCG_DEBUG,
         _("Enable logging of debug messages. Implies verbose. Warning! "
           "This will print private key information to the screen!"), NULL}, \
        {"version", 'V', POPT_ARG_NONE, &options->print_version, 0,
         _("Display the version number and exit."), NULL}, \
        {"lifetime", '\0', POPT_ARG_SHORT, &options->lifetime, 0,
         _("Certificate lifetime (days)."), \
         _("1-3650")}, \
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



}
