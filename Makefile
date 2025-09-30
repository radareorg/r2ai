TARGETS=all clean mrproper user-install install user-uninstall uninstall
$(TARGETS):
	$(MAKE) -C src $<
.PHONY: $(TARGETS)
