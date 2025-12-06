PD=$(shell r2 -H R2_USER_PLUGINS)
SPD=$(shell r2 -H R2_LIBR_PLUGINS)
BF=/bin/dd

all:
	@echo "Run: 'make user-install' to install it in your home"
	@echo "Run: 'make -C src' to recompile the r2.js"

test:
	r2 -i decai.r2.js -c 'decai -e deterministic=true' -caf $(BF)

fmt indent:
	$(MAKE) -C src fmt

user-install:
	mkdir -p "$(PD)"
	cp decai.r2.js $(PD)/decai.r2.js

user-uninstall:
	rm -f $(PD)/decai.r2.js

install:
	make user-install PD=$(SPD)

uninstall:
	make user-uninstall PD=$(SPD)

vs open:
	open -a "Visual Studio Code" src
