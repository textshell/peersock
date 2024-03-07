project('peersock', ['c', 'cpp'],
  default_options: [
    'cpp_std=gnu++17',
    'default_library=static',
    'libsoup:gssapi=disabled',
    'libsoup:gnome=false',
    'libsoup:introspection=disabled',
    'libnice:gupnp=disabled'
    ]
  )

openssl_dep = dependency('openssl', version: '>= 3.3')

if get_option('avoidsoup3')
  libsoup_dep = subproject('libsoup').get_variable('libsoup_dep')
  libnice_dep = subproject('libnice').get_variable('libnice_dep')
else
  libsoup_dep = dependency('libsoup-2.4')
  libnice_dep = dependency('nice')
endif

main_deps = [
  dependency('glib-2.0'),
  dependency('gio-unix-2.0'),
  libsoup_dep,
  libnice_dep,
  dependency('fmt'),
  dependency('libotr'),
  dependency('nlohmann_json', required: false), # debian ships in the default include path without pkgconfig
  openssl_dep,
]

#ide:editable-filelist
main_files = [
  'main.cpp',
  'modes.cpp',
  'peersock.cpp',
  'utils.cpp',
]

executable('peersock', main_files, dependencies: main_deps)
