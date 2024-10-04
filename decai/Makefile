PD=$(shell r2 -H R2_USER_PLUGINS)
SPD=$(shell r2 -H R2_LIBR_PLUGINS)
BF=/bin/dd

all:
	@echo 'You can now use 'decai' command'
	r2 -i decai.r2.js $(BF)

user-install:
	cp decai.r2.js $(PD)/decai.r2.js

user-uninstall:
	rm -f $(PD)/decai.r2.js

install:
	make user-install PD=$(SPD)

uninstall:
	make user-uninstall PD=$(SPD)

vs open:
	open -a "Visual Studio Code" .
