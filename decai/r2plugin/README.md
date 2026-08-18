# decai r2plugin

Boilerplate to embed `decai.r2.js` inside the radare2 core library using the
external plugin system (XPS). Unlike `r2ai/r2plugin`, this does not link any
native code: the r2.js script is converted into a C buffer and registered as
an embedded startup script, so r2 runs it at startup exactly like a file in
the `plugins/*.r2.js` directory (honoring `cfg.plugins`).

The `decai.r2.js` bundle is built from the typescript sources with
`r2frida-compile` (see `make -C src` in the decai directory). The C buffer is
generated at build time with `rax2 -C` (make builds) or `js2c.py` (meson).

## Usage

decai lives inside the r2ai repository, so expose it as `libr/xps/p/decai`:

```console
cd radare2/libr/xps/p
git clone https://github.com/radareorg/r2ai
ln -s r2ai/decai decai
```

For acr/make builds:

```console
cd radare2
make -C libr/xps EXTERNAL_PLUGINS=decai
./configure-plugins
make
```

For meson builds, make `libr/xps/p/meson.build` contain:

```meson
subdir('decai/r2plugin')
```
