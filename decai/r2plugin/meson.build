# decai XPS integration for radare2.
# Included from libr/xps/meson.build when decai lives under libr/xps/p/decai/.
# Unlike native plugins, decai ships no native code: decai.r2.js is embedded
# as a buffer in libr_core and the tiny core plugin registers it with
# r_core_script_embed() so r2 runs it at startup like any plugins/*.r2.js file.

core_plugins += ['decai']

decai_py3 = import('python').find_installation()

r_core_additional_sources += files('core/plugin.c')
r_core_additional_sources += custom_target('decai_r2_js_c',
  input: '../decai.r2.js',
  output: 'decai.r2.js.c',
  command: [decai_py3, files('js2c.py'), '@INPUT@', '@OUTPUT@'],
)
