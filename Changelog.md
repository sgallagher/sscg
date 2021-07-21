# Changes for sscg 3.0

## New features
* Support for OpenSSL 3.0
* Support for outputting named Diffie-Hellman parameter groups
* Support for CentOS Stream 9

## Major version notes
* SSCG now requires OpenSSL 1.1.0 or later.
* sscg will now always output DH parameters to a PEM file. It will default to using the `ffdhe4096` group.
* Generated certificate lifetime now defaults to 398 days, rather than ten years to conform to [modern browser expectations](https://chromium-review.googlesource.com/c/chromium/src/+/2258372).
