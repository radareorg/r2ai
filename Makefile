R2V=$(shell r2 -v)

ifeq ($(R2V),)
MISSING RADARE2
endif

.PHONY: all all.old deps clean deps-global pub lint cilint
.PHONY: install uninstall user-install user-uninstall

all:
	@echo "Usage: Run 'make' in the following subdirectories instead"
	@echo "src/    - Modern C rewrite in form of a native r2 plugin"
	@echo "py/     - The old Python cli and r2 plugin"
	@echo "decai/  - r2js plugin with focus on decompiling"
	@echo "server/ - shellscript to easily run llamacpp and other"
	@false

clean:
	@echo We are clean already

mrproper:
	$(MAKE) clean

