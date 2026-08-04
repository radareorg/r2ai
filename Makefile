TARGETS=all clean mrproper user-install install user-uninstall uninstall fmt indent

$(TARGETS):
	$(MAKE) -C src $@

test: all
	$(MAKE) -C test

.PHONY: $(TARGETS) test
