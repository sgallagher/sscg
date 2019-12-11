project('sscg', 'c',
        version : '2.5.1',
        default_options : [
          'buildtype=debugoptimized',
          'c_std=gnu99',
          'warning_level=1',
          'b_asneeded=true',
        ],
        license : 'MIT',
        meson_version : '>=0.40.0')

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
crypto = dependency('libcrypto')
ssl = dependency('libssl')
path_utils = dependency('path_utils')
talloc = dependency('talloc')

popt = dependency(
    'popt',
    version : '>=1.14',
    required : false)

if popt.found()
    popt_incdirs = include_directories('.')
else
    popt = subproject('popt').get_variable('libpopt_a')
    popt_incdirs = include_directories('subprojects/popt')
endif

has_get_sec_level = cc.has_function(
    'SSL_CTX_get_security_level',
    dependencies: [ ssl ])

has_generator_3 = cc.has_header_symbol(
    'openssl/dh.h',
    'DH_GENERATOR_3',
    dependencies: [ ssl ])

sscg_bin_srcs = [
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
            path_utils,
            popt,
            talloc,
        ],
    include_directories : popt_incdirs,
    install : true,
)

# Fake test to ensure that all sources and headers are formatted properly
test_clang_format = find_program('clang-format')
clang_args = [ '-i' ]
test('test_clang_format', test_clang_format,
     args : clang_args + files(sscg_lib_srcs + sscg_lib_hdrs + sscg_bin_srcs))

create_ca_test = executable(
    'create_ca_test',
    'test/create_ca_test.c',
    link_with : sscg_lib,
        dependencies: [],
    install:false,
)
test('create_ca_test', create_ca_test)

create_csr_test = executable(
    'create_csr_test',
    'test/create_csr_test.c',
    link_with : sscg_lib,
        dependencies: [],
    install:false,
)
test('create_csr_test', create_csr_test)

generate_rsa_key_test = executable(
    'generate_rsa_key_test',
    'test/generate_rsa_key_test.c',
    link_with : sscg_lib,
        dependencies: [],
    install:false,
)
test('generate_rsa_key_test', generate_rsa_key_test)

generate_serial_test = executable(
    'generate_serial_test',
    'test/generate_serial_test.c',
    link_with : sscg_lib,
        dependencies: [],
    install:false,
)
test('generate_serial_test', generate_serial_test)

init_bignum_test = executable(
    'init_bignum_test',
    'test/init_bignum_test.c',
    link_with : sscg_lib,
        dependencies: [],
    install : false,
)
test('init_bignum_test', init_bignum_test)

dhparams_test = executable(
    'dhparams_test',
    'test/dhparams_test.c',
    link_with : sscg_lib,
    dependencies: [],
    install : false
)

# Test generating 512-bit, 1024-bit and 2048-bit DH params with multiple
# generators. 4096-bit and larger takes over ten minutes, so it's excluded from
# the test suite by default.
prime_lengths = [ 512, 1024 ]
dhparam_timeout = 120

if get_option('run_slow_tests')
    prime_lengths = prime_lengths + [ 2048, 4096 ]
    dhparam_timeout = 900
endif

generators = [ 2, 5 ]

if (has_generator_3)
    generators += [ 3 ]
endif

foreach prime_len : prime_lengths
    foreach g : generators
        test('dhparams_test_' + prime_len.to_string() + '_' + g.to_string(),
             dhparams_test,
             args: [ prime_len.to_string(), g.to_string() ],
             timeout: dhparam_timeout)
    endforeach
endforeach



cdata = configuration_data()
cdata.set_quoted('PACKAGE_VERSION', meson.project_version())
cdata.set('HAVE_SSL_CTX_GET_SECURITY_LEVEL', has_get_sec_level)
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
