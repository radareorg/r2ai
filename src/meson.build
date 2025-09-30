project('r2ai', 'c',
  version : '0.1.0',
  default_options : ['warning_level=2', 'c_std=c11']
)

cc = meson.get_compiler('c')

# Prefer pkg-config for radare2 development files, fall back to -Dr2_prefix
r_core_dep = dependency('r_core', method: 'pkg-config', required: false)

if not r_core_dep.found()
  is_windows_like = host_machine.system() == 'windows'
  if is_windows_like
    if get_option('r2_prefix') != ''
      p = get_option('r2_prefix')
      libdirs = [ join_paths(p, 'lib'), join_paths(p, 'radare2', 'lib') ]
      rcore_lib = cc.find_library('r_core', dirs: libdirs, required: false)
      if not rcore_lib.found()
        rcore_lib = cc.find_library('libr_core', dirs: libdirs, required: false)
      endif
      if rcore_lib.found()
        incdirs = [ join_paths(p, 'include'), join_paths(p, 'include', 'libr') ]
        rcore_inc = include_directories(incdirs)
        r_core_dep = declare_dependency(dependencies: [rcore_lib], include_directories: rcore_inc)
      else
        error('r_core not found: set -Dr2_prefix=<prefix> or install radare2 development files')
      endif
    else
      error('r_core not found: install radare2 development files or set -Dr2_prefix=<prefix>')
    endif
  else
    error('r_core not found: install radare2 development files or enable pkg-config')
  endif
endif

# Common compile flags similar to the Makefile
c_args = []
if cc.get_id() == 'gcc' or cc.get_id() == 'clang'
  c_args += ['-Wall', '-g', '-fPIC']
elif cc.get_id() == 'msvc'
  c_args += ['/Zi']
endif

srcs = files(
  'r2ai.c',
  'auto.c',
  'vdb.c',
  'tools.c',
  'messages.c',
  'anthropic.c',
  'r2ai_http.c',
  'openai.c',
  'markdown.c',
)

# Shared library (plugin)
shared_lib = shared_library(
  'r2ai',
  srcs,
  install: true,
  c_args: c_args,
  dependencies: [r_core_dep]
)

# Command-line executable (links the same objects plus main.c)
exe = executable(
  'r2ai',
  [ 'main.c' ],
  link_with: shared_lib,
  install: true,
  c_args: c_args,
  dependencies: [r_core_dep]
)
