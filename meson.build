project('peersock', ['c', 'cpp'], default_options: ['cpp_std=gnu++17'])

openssl_dep = dependency('openssl', version: '>= 3.3')

#libsoup_static_dep = subproject('libsoup').get_variable('libsoup_static_dep')

main_deps = [
  dependency('glib-2.0'),
  #libsoup_static_dep, # system libsoup caused 100% cpu usage on debian buster:
  dependency('libsoup-2.4'),
  dependency('nice'),
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
