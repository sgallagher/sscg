# This file is part of sscg.
#
# sscg is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# sscg is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with sscg.  If not, see <http://www.gnu.org/licenses/>.
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.  If you modify
# file(s) with this exception, you may extend this exception to your
# version of the file(s), but you are not obligated to do so.  If you
# do not wish to do so, delete this exception statement from your
# version.  If you delete this exception statement from all source
# files in the program, then also delete it here.
#
# Copyright 2019-2023 by Stephen Gallagher <sgallagh@redhat.com>

project(
  'sscg',
  'c',
version : '3.0.4',
default_options : ['buildtype=debugoptimized', 'c_std=gnu99', 'warning_level=1', 'b_asneeded=true'],
license : 'GPL-3.0-or-later WITH OpenSSL-exception',
meson_version : '>=0.44.0'
)

cc = meson.get_compiler('c')
test_cflags = [
  '-Wpointer-arith',
  '-Wmissing-declarations',
  '-Wmissing-prototypes',
  '-Wstrict-prototypes',
  '-Wuninitialized',
  '-Werror=implicit',
  '-Werror=init-self',
  '-Werror=main',
  '-Werror=missing-braces',
  '-Werror=return-type',
  '-Werror=array-bounds',
  '-Werror=write-strings',
  '-DG_LOG_USE_STRUCTURED',
]

foreach cflag: test_cflags
  if cc.has_argument(cflag)
    add_project_arguments(cflag, language : 'c')
  endif
endforeach

pkg = import('pkgconfig')

crypto = dependency('libcrypto11', version: '>= 1.1.0', required: false)
if crypto.found()
else
    crypto = dependency('libcrypto', version: '>= 1.1.0')
endif

ssl = dependency('libssl11', version: '>= 1.1.0', required: false)
if ssl.found()
else
    ssl = dependency('libssl', version: '>= 1.1.0')
endif

path_utils = dependency('path_utils')
talloc = dependency('talloc')

popt = dependency(
    'popt',
    version : '>=1.14',
    required : true)

has_evp_rsa_gen = cc.has_header_symbol(
    'openssl/rsa.h',
    'EVP_RSA_gen',
    dependencies: [ crypto ])

has_ossl_param = cc.has_header_symbol(
    'openssl/core.h',
    'OSSL_PARAM')

sscg_bin_srcs = [
    'src/arguments.c',
    'src/sscg.c',
]

sscg_lib_srcs = [
    'src/authority.c',
    'src/bignum.c',
    'src/cert.c',
    'src/dhparams.c',
    'src/io_utils.c',
    'src/key.c',
    'src/x509.c',
]

sscg_lib_hdrs = [
    'include/authority.h',
    'include/bignum.h',
    'include/cert.h',
    'include/dhparams.h',
    'include/io_utils.h',
    'include/key.h',
    'include/sscg.h',
    'include/x509.h',
]

sscg_lib = static_library(
    'sscg',
    sources : sscg_lib_srcs,
    dependencies : [
        crypto,
        ssl,
        talloc,
    ],
    install : false,
    pic : true,
)

sscg = executable(
    'sscg',
    sscg_bin_srcs,
    link_with : sscg_lib,
    dependencies : [
        crypto,
        path_utils,
        popt,
        ssl,
        talloc,
    ],
    include_directories : include_directories('.'),
    install : true,
)

# Fake test to ensure that all sources and headers are formatted properly
test_clang_format = find_program('clang-format', required: false)
if not test_clang_format.found()
    test_clang_format = disabler()
endif

clang_args = [ '-i' ]
test('test_clang_format', test_clang_format,
     args : clang_args + files(sscg_lib_srcs + sscg_lib_hdrs + sscg_bin_srcs))

create_ca_test = executable(
    'create_ca_test',
    'test/create_ca_test.c',
    link_with : sscg_lib,
        dependencies: [ crypto ],
    install:false,
)
test('create_ca_test', create_ca_test, timeout: 120)

create_csr_test = executable(
    'create_csr_test',
    'test/create_csr_test.c',
    link_with : sscg_lib,
        dependencies: [ crypto ],
    install:false,
)
test('create_csr_test', create_csr_test, timeout: 120)

generate_rsa_key_test = executable(
    'generate_rsa_key_test',
    'test/generate_rsa_key_test.c',
    link_with : sscg_lib,
        dependencies: [ crypto ],
    install:false,
)
test('generate_rsa_key_test', generate_rsa_key_test, timeout: 120)

generate_serial_test = executable(
    'generate_serial_test',
    'test/generate_serial_test.c',
    link_with : sscg_lib,
        dependencies: [ crypto ],
    install:false,
)
test('generate_serial_test', generate_serial_test)

init_bignum_test = executable(
    'init_bignum_test',
    'test/init_bignum_test.c',
    link_with : sscg_lib,
        dependencies: [ crypto ],
    install : false,
)
test('init_bignum_test', init_bignum_test)


# Test generating 512-bit, 1024-bit and 2048-bit and 4096 DH params with
# multiple generators. 2048-bit and larger takes a long time, so they are
# excluded from the test suite by default.

prime_lengths = [ 512, 1024 ]
dhparam_timeout = 240

if get_option('run_slow_tests')
    prime_lengths = prime_lengths + [ 2048, 4096 ]
    dhparam_timeout = 900
endif

generators = [ 2, 5 ]

dhparams_test = executable(
    'dhparams_test',
    'test/dhparams_test.c',
    link_with : sscg_lib,
    dependencies: [ crypto ],
    install : false
)

foreach prime_len : prime_lengths
    foreach g : generators
        test('dhparams_test_' + prime_len.to_string() + '_' + g.to_string(),
             dhparams_test,
             args: [ prime_len.to_string(), g.to_string() ],
             timeout: dhparam_timeout)
    endforeach
endforeach


named_dhparams_test = executable(
    'named_dhparams_test',
    'test/named_dhparams_test.c',
    link_with : sscg_lib,
    dependencies: [ crypto ],
    install : false,
)
# takes *very* long on some architectures like Debian armel
test('named_dhparams_test', named_dhparams_test, timeout : 2700)


test_env = environment()
test_env.set('LC_ALL', 'C')
test_env.set ('MESON_SOURCE_ROOT', meson.current_source_dir())
test_env.set ('MESON_BUILD_ROOT', meson.current_build_dir())

test_cert_validity = find_program(
    'test/test_cert_validity.sh',
    required: true,
)

hash_algs = [
    'sha256',
    'sha384',
    'sha512',
]

cipher_algs = [
    'des-ede3-cbc',
    'aes-256-cbc',
]

key_strengths = [
    '512',
    '1024',
    '2048',
    '4096',
    '7680',
    '8192',
    '15360',
]

foreach hash_alg : hash_algs
    foreach cipher_alg : cipher_algs
        foreach key_strength : key_strengths
            test(
                'test_cert_validity_' + hash_alg + '_' + cipher_alg + '_' + key_strength,
                test_cert_validity,
                env: test_env,
            )
        endforeach
    endforeach
endforeach


cdata = configuration_data()
cdata.set_quoted('PACKAGE_VERSION', meson.project_version())
cdata.set('HAVE_SSL_EVP_RSA_GEN', has_evp_rsa_gen)
cdata.set('HAVE_OSSL_PARAM', has_ossl_param)
configure_file(
    output : 'config.h',
    configuration : cdata)

# Generate a manpage from the POPT documentation
help2man = find_program('help2man')

manpage = custom_target('manpage',
    output : 'sscg.8',
    capture : true,
    command : [
        help2man,
        '-s', '8',
        '-n', 'Tool for generating x.509 certificates',
        '-N',
        sscg,
    ],
    install : true,
    build_by_default : true,
    install_dir : join_paths(
        get_option('prefix'),
        get_option('mandir'),
        'man8'),
)
