PLUGIN_NAME=decai
R2F_C_FLAGS=-c -S

all: build

build:
	r2pm -r r2frida-compile $(R2F_C_FLAGS) -o ../$(PLUGIN_NAME).r2.js main.ts

test: build
	r2 -i ../$(PLUGIN_NAME).r2.js /bin/ls

clean:
	rm -rf out node_modules ../$(PLUGIN_NAME).r2.js

.PHONY: all build test clean
