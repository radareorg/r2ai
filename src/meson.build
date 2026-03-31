project('r2ai', 'c',
  version : '1.3.4',
  default_options : ['warning_level=2', 'c_std=c11']
)

cc = meson.get_compiler('c')
r2_prefix = get_option('r2_prefix')

r2_libdirs = []
r2_incdirs = []

# If pkg-config fails, set up fallback search paths from r2_prefix
r_core_dep = dependency('r_core', method: 'pkg-config', required: false)
if not r_core_dep.found()
  r2_libdirs = [
    join_paths(r2_prefix, 'lib'),
    join_paths(r2_prefix, 'lib64'),
    join_paths(r2_prefix, 'radare2', 'lib'),
    join_paths(r2_prefix, 'radare2', 'lib64'),
    join_paths(r2_prefix, 'mingw64', 'lib'),
    join_paths(r2_prefix, 'bin'),
  ]
  r2_incdirs = [
    join_paths(r2_prefix, 'include'),
    join_paths(r2_prefix, 'include', 'libr'),
    join_paths(r2_prefix, 'include', 'radare2'),
    join_paths(r2_prefix, 'radare2', 'include'),
  ]
endif

# Filter include dirs to only those that exist
fs = import('fs')
r2_valid_incdirs = []
foreach d : r2_incdirs
  if fs.is_dir(d)
    r2_valid_incdirs += [d]
  endif
endforeach

# Resolve all radare2 dependencies: pkg-config first, then manual search
r2_deps = []
foreach name : ['r_core', 'r_util', 'r_cons', 'r_config', 'r_socket']
  dep = dependency(name, method: 'pkg-config', required: false)
  if not dep.found() and r2_libdirs.length() > 0
    foreach libname : [name, 'lib' + name]
      lib = cc.find_library(libname, dirs: r2_libdirs, required: false)
      if lib.found()
        dep = declare_dependency(
          dependencies: [lib],
          include_directories: include_directories(r2_valid_incdirs),
        )
        break
      endif
    endforeach
  endif
  if name == 'r_core' and not dep.found()
    error('r_core not found: install radare2 dev files, set PKG_CONFIG_PATH, or use -Dr2_prefix=<prefix>')
  endif
  r2_deps += [dep]
endforeach

common_deps = r2_deps + [cc.find_library('m', required: false)]

srcs = files(
  'anthropic.c',
  'auto.c',
  'apikeys.c',
  'gemini.c',
  'http.c',
  'json.c',
  'wizard.c',
  'llm.c',
  'markdown.c',
  'messages.c',
  'openai.c',
  'query.c',
  'r2ai.c',
  'rawtools.c',
  'tools.c',
  'vdb.c',
)

shared_lib = shared_library('r2ai', srcs,
  install: true,
  dependencies: common_deps,
)

executable('r2ai', 'main.c',
  link_with: shared_lib,
  install: true,
  dependencies: common_deps,
)
