PLUGIN_NAME=decai
R2F_C_FLAGS=-c -S
R2FRIDA_COMPILE?=r2pm -r r2frida-compile

all: build

build:
	$(R2FRIDA_COMPILE) $(R2F_C_FLAGS) -o ../$(PLUGIN_NAME).r2.js main.ts

test: build
	r2 -i ../$(PLUGIN_NAME).r2.js -q -c 'af;decai -d' /bin/ls

fmt:
	deno fmt

clean:
	rm -rf out node_modules ../$(PLUGIN_NAME).r2.js

.PHONY: all build test clean
