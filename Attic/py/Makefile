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

ifeq ($(R2PM_BINDIR),)
MISSING RADARE2
endif

LINTED=r2ai/code_block.py
LINTED+=r2ai/bubble.py
LINTED+=r2ai/const.py
LINTED+=r2ai/backend/kobaldcpp.py
# LINTED+=r2ai/index.py
# LINTED+=r2ai/voice.py
# LINTED+=r2ai/anthropic.py
r2ai-python py python r2aipy: venv
	@./r2ai.sh

large:
	. venv/bin/activate ; $(PYTHON) -m r2ai.cli -l

all.old:
	@test -n "${VIRTUAL_ENV}" || (echo "Run:"; echo ". venv/bin/activate" ; exit 1)
	$(PYTHON) main.py || $(MAKE) deps

venv:
	$(PYTHON) -m venv venv
	if [ -z "`find venv | grep llama_cpp`" ]; then . venv/bin/activate ; pip install . ; fi

deps: venv
	#test -n "${VIRTUAL_ENV}" || (echo "Run: . venv/bin/activate" ; exit 1)
	. venv/bin/activate && export CMAKE_ARGS="-DLLAMA_METAL=on -DLLAMA_METAL_EMBED_LIBRARY=ON" && \
		pip install --force-reinstall -U --no-cache-dir .
clean:
	rm -rf venv
	rm -rf build
	find . -name "*.egg-info" -exec rm -rf {} +

user-install:
	rm -f $(R2PM_BINDIR)/r2ai
	ln -fs $(PWD)/r2ai.sh $(R2PM_BINDIR)/r2ai

install: user-install
	-mkdir -p /usr/local/share/man/man1/r2ai.1
	-cp doc/usage/r2ai.1 /usr/local/share/man/man1/r2ai.1

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

pylint lint cilint:
	. venv/bin/activate ; pylint $(LINTED)

lintall:
	pylint *.py r2ai/*.py

.PHONY: lint lintall

deps-global:
	export CMAKE_ARGS="-DLLAMA_METAL=on -DLLAMA_METAL_EMBED_LIBRARY=ON" && \
		$(PIP) install --force-reinstall -U --break-system-packages --no-cache-dir .

