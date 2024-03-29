R2_USER_PLUGINS=$(shell r2 -H R2_USER_PLUGINS)
PWD=$(shell pwd)
R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)
PIP=python -m pip

ifeq ($(R2PM_BINDIR),)
FATAL ERROR
endif

all:
	@test -n "${VIRTUAL_ENV}" || (echo "Run:"; echo ". venv/bin/activate" ; exit 1)
	python3 main.py || $(MAKE) deps

venv:
	python -m venv venv

deps: venv
	test -n "${VIRTUAL_ENV}" || (echo "Run: . venv/bin/activate" ; exit 1)
	export CMAKE_ARGS="-DLLAMA_METAL=on -DLLAMA_METAL_EMBED_LIBRARY=ON" && \
		pip install --force-reinstall -U -r requirements.txt --no-cache-dir
	$(MAKE) vectordb

clean:
	rm -rf venv

deps-global:
	export CMAKE_ARGS="-DLLAMA_METAL=on -DLLAMA_METAL_EMBED_LIBRARY=ON" && \
		$(PIP) install --force-reinstall -U -r requirements.txt --break-system-packages --no-cache-dir

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
