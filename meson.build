project('httpknock', 'c')

add_project_arguments('-fPIE', language : 'c')
add_project_arguments('-fstack-protector-all', language : 'c')
add_project_arguments('-D_FORTIFY_SOURCE=2', language : 'c')
add_project_arguments('-O2', language : 'c')
link_args = '-Wl,-z,relro,-z,now'

server_sources = [
  'src/knock.c',
  'src/db.c'
]

glib = dependency('glib-2.0')
soup = dependency('libsoup-3.0')
nft = dependency('libnftables')
sqlite = dependency('sqlite3')
jansson = dependency('jansson')

server_deps = [soup, nft, sqlite, jansson]

if not get_option('dev')
     # have to be passed explicitly for static linking
     gmp = dependency('gmp')
     libnftnl = dependency('libnftnl')
     xtables = dependency('xtables')
     server_deps += [gmp, libnftnl, xtables]
endif

executable('httpknock-server', server_sources, dependencies : server_deps, link_args: link_args)

cred_sources = [
  'src/addcred.c',
  'src/db.c'
]
cred_deps = [sqlite, glib]
executable('httpknock-addcred', cred_sources, dependencies : cred_deps)

cmd_sources = [
  'src/knock-cmd.c'
]
cmd_deps = [glib, soup]
executable('httpknock', cmd_sources, dependencies : cmd_deps)

if get_option('dev')
  test_sources = [
    'tests/mocks.c'
  ]
  python_dep = dependency('python3-embed')
  test_deps = [python_dep]
  library('mocks', test_sources, dependencies : test_deps)
endif
