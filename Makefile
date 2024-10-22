R2_USER_PLUGINS=$(shell r2 -H R2_USER_PLUGINS)
PWD=$(shell pwd)
R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)
PV=3.12
ifeq ($(shell which python${PV} > /dev/null && echo ok),ok)
PYTHON?=python${PV}
else
PYTHON?=python3
endif
PIP=$(PYTHON) -m pip

LINTED=r2ai/code_block.py
LINTED+=r2ai/bubble.py
LINTED+=r2ai/const.py
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
	source venv/bin/activate ; $(PYTHON) -m r2ai.cli -l

all.old:
	@test -n "${VIRTUAL_ENV}" || (echo "Run:"; echo ". venv/bin/activate" ; exit 1)
	$(PYTHON) main.py || $(MAKE) deps

venv:
	$(PYTHON) -m venv venv
	if [ -z "`find venv | grep llama_cpp`" ]; then source venv/bin/activate ; pip install . ; fi

deps: venv
	#test -n "${VIRTUAL_ENV}" || (echo "Run: . venv/bin/activate" ; exit 1)
	source venv/bin/activate && export CMAKE_ARGS="-DLLAMA_METAL=on -DLLAMA_METAL_EMBED_LIBRARY=ON" && \
		pip install --force-reinstall -U --no-cache-dir .

clean:
	rm -rf venv
	rm -rf build
	find . -name "*.egg-info" -exec rm -rf {} +

mrproper:
	$(MAKE) clean

deps-global:
	export CMAKE_ARGS="-DLLAMA_METAL=on -DLLAMA_METAL_EMBED_LIBRARY=ON" && \
		$(PIP) install --force-reinstall -U --break-system-packages --no-cache-dir .

user-install:
	rm -f $(R2PM_BINDIR)/r2ai-server
	ln -fs $(PWD)/r2ai-server/r2ai-server $(R2PM_BINDIR)/r2ai-server
	rm -f $(R2PM_BINDIR)/r2ai
	ln -fs $(PWD)/r2ai.sh $(R2PM_BINDIR)/r2ai

install: user-install
	-mkdir -p /usr/local/share/man/man1/r2ai.1
	-cp doc/usage/r2ai.1 /usr/local/share/man/man1/r2ai.1

install-decai:
	$(MAKE) -C decai user-install

install-server:
	$(MAKE) -C r2ai-server user-install

install-plugin user-install-plugin:
	ln -fs $(PWD)/r2ai/plugin.py $(R2_USER_PLUGINS)/r2ai.py

uninstall user-uninstall:
	rm -f $(R2PM_BINDIR)/r2ai
	-rm -f /usr/local/share/man/man1/r2ai.1

user-uninstall-plugin uninstall-plugin:
	rm -f $(R2_USER_PLUGINS)/r2ai.py

pub:
	$(PYTHON) -m build
	twine check dist/*
	twine upload -u __token__ --repository-url https://upload.pypi.org/legacy/ --verbose dist/*

cilint:
	pylint $(LINTED)

lint:
	pylint *.py r2ai/*.py
