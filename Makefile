R2_USER_PLUGINS=$(shell r2 -H R2_USER_PLUGINS)
PWD=$(shell pwd)
R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)
# Note that a bunch of packages are not available for 3.12 yet
ifeq ($(shell which python3.11 > /dev/null && echo ok),ok)
PYTHON?=python3.11
else
PYTHON?=python3
endif
PIP=$(PYTHON) -m pip

LINTED=r2ai/code_block.py
LINTED+=r2ai/bubble.py
LINTED+=r2ai/const.py
LINTED+=main.py
LINTED+=r2ai/backend/kobaldcpp.py
# LINTED+=r2ai/index.py
# LINTED+=r2ai/voice.py
# LINTED+=r2ai/anthropic.py

ifeq ($(R2PM_BINDIR),)
FATAL ERROR
endif

.PHONY: all all.old deps clean deps-global pub lint cilint
.PHONY: install uninstall user-install user-uninstall

all: venv
	@./r2ai.sh

large:
	. venv/bin/activate ; $(PYTHON) main.py -l

all.old:
	@test -n "${VIRTUAL_ENV}" || (echo "Run:"; echo ". venv/bin/activate" ; exit 1)
	$(PYTHON) main.py || $(MAKE) deps

venv:
	$(PYTHON) -m venv venv
	if [ -z "`find venv | grep llama_cpp`" ]; then . venv/bin/activate ; pip install -r requirements.txt ; fi

deps: venv
	#test -n "${VIRTUAL_ENV}" || (echo "Run: . venv/bin/activate" ; exit 1)
	. venv/bin/activate && export CMAKE_ARGS="-DLLAMA_METAL=on -DLLAMA_METAL_EMBED_LIBRARY=ON" && \
		pip install --force-reinstall -U -r requirements.txt --no-cache-dir
	$(MAKE) vectordb

clean:
	rm -rf venv vectordb vdb

mrproper:
	$(MAKE) clean

deps-global:
	export CMAKE_ARGS="-DLLAMA_METAL=on -DLLAMA_METAL_EMBED_LIBRARY=ON" && \
		$(PIP) install --force-reinstall -U -r requirements.txt --break-system-packages --no-cache-dir

vdb vectordb:
	git clone https://github.com/kagisearch/vectordb vdb
	cat vdb/setup.py | grep -v tensorflow_text > .x && mv .x vdb/setup.py
	. venv/bin/activate \
		&& cd vdb \
		&& $(PIP) install setuptools tensorflow_hub \
		&& $(PYTHON) setup.py build \
		&& $(PYTHON) setup.py install

install user-install:
	ln -fs $(PWD)/r2ai-server $(R2PM_BINDIR)/r2ai-server
	ln -fs $(PWD)/main.py $(R2_USER_PLUGINS)/r2ai.py
	ln -fs $(PWD)/r2ai.sh $(R2PM_BINDIR)/r2ai
	-mkdir -p /usr/local/share/man/man1/r2ai.1
	-cp doc/usage/r2ai.1 /usr/local/share/man/man1/r2ai.1
	$(MAKE) -C native/cxx user-uninstall

uninstall user-uninstall:
	rm -f $(R2_USER_PLUGINS)/r2ai.py
	rm -f $(R2PM_BINDIR)/r2ai
	-rm -f /usr/local/share/man/man1/r2ai.1

pub:
	$(PYTHON) setup.py build sdist
	twine check dist/*
	twine upload -u __token__ --repository-url https://upload.pypi.org/legacy/ --verbose dist/*

cilint:
	pylint $(LINTED)

lint:
	pylint *.py r2ai/*.py
