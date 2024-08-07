PD=$(shell r2 -H R2_USER_PLUGINS)

all:
	@echo 'You can now use 'decai' command'
	r2 -i decai.r2.js /usr/bin/sed

user-install:
	cp decai.r2.js $(PD)/decai.r2.js

user-uninstall:
	rm -f $(PD)/decai.r2.js

vs open:
	open -a "Visual Studio Code" .
