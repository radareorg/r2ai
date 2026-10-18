# r2plugin

This directory contains the make and meson files required to link r2ai
inside radare2 through the external plugin system (XPS).

```console
cd radare2
make -C libr/xps EXTERNAL_PLUGINS=r2ai
./configure-plugins
make
```

For meson builds, place this repository at `libr/xps/p/r2ai` and make
`libr/xps/p/meson.build` include:

```meson
subdir('r2ai/r2plugin')
```

## WASI HTTP build

Use a radare2 checkout with the host HTTP bridge and place this repository at
`libr/xps/p/r2ai`. From that radare2 checkout:

```sh
echo 'EXTERNAL_PLUGINS+=r2ai' >> libr/xps/config.mk
make -C libr/xps
WASI_HTTP=1 sys/wasi-api.sh
```

This links the C plugin into the reactor; it does not load a native shared
library at runtime. Enable HTTP in the host adapter. The `auto` backend selects
`r_socket_http_get/post`, preserving provider authentication headers and JSON
bodies, subject to the radare2 sandbox. `--disable-network` also denies these calls.

WASI excludes POSIX signal/alarm handling; the host controls request timeouts,
not `r2ai.http.timeout`. Normal queries and model listing use buffered HTTP.
Vertex's automatic `gcloud` authentication and background tasks requiring
threads are unavailable. Explicit shell backends (`system`/`curl`) cannot work;
use `auto` or `socket`. Browser CORS and restricted-header rules still apply.
