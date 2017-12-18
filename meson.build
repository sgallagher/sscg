project('sscg', 'c',
        version : '2.3.0',
        default_options : [
          'buildtype=debugoptimized',
          'c_std=gnu99',
          'warning_level=1',
          'b_asneeded=true',
        ],
        license : 'MIT',
        meson_version : '>=0.36.0')

sscg_version = '2.3.0'


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
path_utils = dependency('path_utils')
popt = dependency('popt')
talloc = dependency('talloc')

sscg_lib_srcs = [
    'src/authority.c',
    'src/bignum.c',
    'src/key.c',
    'src/service.c',
    'src/x509.c',
]

sscg_lib_hdrs = [
    'include/authority.c',
    'include/bignum.h',
    'include/key.h',
    'include/service.h',
    'include/x509.h',
]

sscg_lib = static_library(
    'sscg',
    sources : sscg_lib_srcs,
    dependencies : [
        crypto,
        talloc,
    ],
    install : false,
    pic : true,
)

sscg = executable(
    'sscg',
    'src/sscg.c',
    link_with : sscg_lib,
        dependencies : [
            path_utils,
            popt,
            talloc,
        ],
    install : true,
)

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

cdata = configuration_data()
cdata.set('version', meson.project_version())
configure_file(
    input : 'config.h.in',
    output : 'config.h',
    configuration : cdata)

