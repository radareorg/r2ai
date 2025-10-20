TARGETS=all clean mrproper user-install install user-uninstall uninstall fmt indent

$(TARGETS):
	$(MAKE) -C src $@

.PHONY: $(TARGETS)
