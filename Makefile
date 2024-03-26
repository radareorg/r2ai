R2_USER_PLUGINS=$(shell r2 -H R2_USER_PLUGINS)
PWD=$(shell pwd)
R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)
PIP=python -m pip

ifeq ($(R2PM_BINDIR),)
FATAL ERROR
endif

all:
	python3 main.py || $(MAKE) deps

deps:
	export CMAKE_ARGS="-DLLAMA_METAL=on -DLLAMA_METAL_EMBED_LIBRARY=ON" && \
		$(PIP) install -U -r requirements.txt --break-system-packages

vectordb:
	git clone https://github.com/kagisearch/vectordb
	cd vectordb && python setup.py build

install user-install:
	ln -fs $(PWD)/main.py $(R2_USER_PLUGINS)/r2ai.py
	ln -fs $(PWD)/main.py $(R2PM_BINDIR)/r2ai
	$(MAKE) -C native/cxx user-uninstall

uninstall user-uninstall:
	rm -f $(R2_USER_PLUGINS)/r2ai.py
	rm -f $(R2PM_BINDIR)/r2ai
