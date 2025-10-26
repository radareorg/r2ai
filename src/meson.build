project('r2ai', 'c',
  version : '1.2.2',
  default_options : ['warning_level=2', 'c_std=c11']
)

cc = meson.get_compiler('c')

# radare2 core dependency: use pkg-config when available. Do not fall back
# to CMake-based dependency discovery; instead, if pkg-config fails, try
# locating the library under user-provided prefixes (see -Dr2_prefix).
r_core_dep = dependency('r_core', method: 'pkg-config', required: false)

# Centralized resolution results: when we locate `r_core` manually below we
# record the library and include search directories in `r2_libdirs` and
# `r2_incdirs`. Later lookups for other `r_*` libraries will assume they
# live in the same locations, avoiding repeating complex prefix search
# logic.
r2_libdirs = []
r2_incdirs = []

# If pkg-config didn't yield an r_core dependency, fall back to manual
# discovery logic below (search common prefixes / extracted zips).
if not r_core_dep.found()
  # On Windows prefer explicit discovery like other third_party projects do:
  # 1) ask an installed `radare2` binary for its lib/include/plugin dirs
  #    (via `radare2 -H R2_LIBDIR` / `R2_INCDIR`),
  # 2) fall back to -Dr2_prefix provided by CI, and
  # 3) try common locations such as C:\\radare2\\lib and <prefix>/bin.
  # This avoids Meson's CMake-based dependency fallback which doesn't work
  # reliably with radare2 release zips on Windows.
  is_windows_like = host_machine.system() == 'windows' or cc.get_id() == 'msvc' or cc.get_id() == 'clang-cl'

  # Simpler, robust Windows behavior mirroring third_party projects:
  # Try to find r_core by checking a small list of likely library dirs.
  if is_windows_like
    r2libdirs = []
    # prefer explicit prefix if given
    if get_option('r2_prefix') != ''
      p = get_option('r2_prefix')
      r2libdirs += [ join_paths(p, 'lib'), join_paths(p, 'radare2', 'lib') ]
    endif
    # repository-local radare2 (used by some subprojects) and conventional path
    r2libdirs += [ meson.current_source_dir() + '/radare2/lib', 'C:/radare2/lib']

    # try to find r_core in the candidate dirs (MSVC import libs or mingw import libs)
    rcore_lib = cc.find_library('r_core', dirs: r2libdirs, required: false)
    if not rcore_lib.found()
      rcore_lib = cc.find_library('libr_core', dirs: r2libdirs, required: false)
    endif

    if rcore_lib.found()
      # basic include candidates
      incdirs = []
      if get_option('r2_prefix') != ''
        p = get_option('r2_prefix')
        incdirs += [ join_paths(p, 'include', 'libr'), join_paths(p, 'include') ]
      endif
      rcore_inc = include_directories(incdirs)
      r_core_dep = declare_dependency(dependencies: [rcore_lib], include_directories: rcore_inc)
      # Remember resolved dirs for other r_* lookups
      r2_libdirs = r2libdirs
      r2_incdirs = incdirs
    else
      error('Windows dependency lookup for r_core failed: ensure radare2 is installed and pass -Dr2_prefix=<prefix> (e.g. C:/radare2)')
    endif
  else
    # Non-Windows: try locating radare2 from environment-provided prefixes. This
    # helps CI on Unix where pkg-config may not be installed.
    r2_prefixes = []
    if get_option('r2_prefix') != ''
      r2_prefixes += [get_option('r2_prefix')]
    endif

    found = false
    foreach p : r2_prefixes
      # Common library/include locations under a provided prefix.
      libdirs = [
        join_paths(p, 'lib'),
        join_paths(p, 'lib64'),
        join_paths(p, 'radare2', 'lib'),
        join_paths(p, 'radare2', 'lib64'),
        join_paths(p, 'mingw64', 'lib'),
      ]
      incdirs = [
        join_paths(p, 'include'),
        join_paths(p, 'radare2', 'include'),
        join_paths(p, 'include', 'radare2'),
      ]
      extra_libdirs = libdirs + [ join_paths(p, 'bin') ]
      candidate_names = [ 'r_core', 'r_core-6', 'r_core6', 'r_core64', 'libr_core' ]
      foreach name : candidate_names
        rcore_lib = cc.find_library(name, dirs: extra_libdirs, required: false)
        if rcore_lib.found()
          rcore_inc = include_directories(incdirs + [ join_paths(p, 'include', 'libr') ])
          r_core_dep = declare_dependency(dependencies: [rcore_lib], include_directories: rcore_inc)
          # Record the successful prefix and candidate lib/include dirs so
          # other r_* dependencies can be looked up in the same locations.
          r2_libdirs = extra_libdirs
          r2_incdirs = incdirs + [ join_paths(p, 'include', 'libr') ]
          found = true
          break
        endif
      endforeach
      if found
        break
      endif
    endforeach

    if not found
      error('Dependency lookup for r_core failed: install radare2 development files or provide pkg-config paths or set the meson option -Dr2_prefix=<prefix>')
    endif
  endif
endif

# Resolve other r_* dependencies assuming same paths as r_core
r_util_dep = dependency('r_util', method: 'pkg-config', required: false)
if not r_util_dep.found() and r2_libdirs.length() > 0
  foreach name : ['r_util', 'libr_util']
    ulib = cc.find_library(name, dirs: r2_libdirs, required: false)
    if ulib.found()
      uinc = include_directories(r2_incdirs)
      r_util_dep = declare_dependency(dependencies: [ulib], include_directories: uinc)
      break
    endif
  endforeach
endif
if not r_util_dep.found()
  warning('r_util dependency not found via pkg-config or same paths as r_core; build may fail on systems without radare2 dev files')
endif

r_cons_dep = dependency('r_cons', method: 'pkg-config', required: false)
if not r_cons_dep.found() and r2_libdirs.length() > 0
  foreach name : ['r_cons', 'libr_cons']
    clib = cc.find_library(name, dirs: r2_libdirs, required: false)
    if clib.found()
      cinc = include_directories(r2_incdirs)
      r_cons_dep = declare_dependency(dependencies: [clib], include_directories: cinc)
      break
    endif
  endforeach
endif
if not r_cons_dep.found()
  warning('r_cons dependency not found via pkg-config or same paths as r_core; console helpers may be unavailable')
endif

r_config_dep = dependency('r_config', method: 'pkg-config', required: false)
if not r_config_dep.found() and r2_libdirs.length() > 0
  foreach name : ['r_config', 'libr_config']
    clib = cc.find_library(name, dirs: r2_libdirs, required: false)
    if clib.found()
      cinc = include_directories(r2_incdirs)
      r_config_dep = declare_dependency(dependencies: [clib], include_directories: cinc)
      break
    endif
  endforeach
endif
if not r_config_dep.found()
  warning('r_config dependency not found via pkg-config or same paths as r_core; console helpers may be unavailable')
endif

r_socket_dep = dependency('r_socket', method: 'pkg-config', required: false)
if not r_socket_dep.found() and r2_libdirs.length() > 0
  foreach name : ['r_socket', 'libr_socket']
    slib = cc.find_library(name, dirs: r2_libdirs, required: false)
    if slib.found()
      sinc = include_directories(r2_incdirs)
      r_socket_dep = declare_dependency(dependencies: [slib], include_directories: sinc)
      break
    endif
  endforeach
endif
if not r_socket_dep.found()
  warning('r_socket dependency not found via pkg-config or same paths as r_core; socket helpers may be unavailable')
endif

# Math library dependency (needed for log, sqrt, etc.)
m_dep = cc.find_library('m', required: false)

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
  'llm.c',
  'tools.c',
  'query.c',
  'rawtools.c',
  'messages.c',
  'anthropic.c',
  'http.c',
  'openai.c',
  'markdown.c',
)

# Shared library (plugin)
shared_lib = shared_library(
  'r2ai',
  srcs,
  install: true,
  c_args: c_args,
  dependencies: [r_core_dep, r_util_dep, r_cons_dep, r_config_dep, r_socket_dep, m_dep]
)

# Command-line executable (links the same objects plus main.c)
exe = executable(
  'r2ai',
  [ 'main.c' ],
  link_with: shared_lib,
  install: true,
  c_args: c_args,
  dependencies: [r_core_dep, r_util_dep, r_cons_dep, r_config_dep, r_socket_dep, m_dep]
)
