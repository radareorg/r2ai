include ./CONFIG

UNAME=$(shell uname)
SUDO?=sudo
DEPENDS=
CROSSARCH=x64
R2CFG_FLAGS?=
PWD=$(shell pwd)
PACKAGE_DIR?=${PWD}
LIBEXT=$(shell r2 -H R2_LIBEXT)

R2_VERSION=$(shell r2 -qv)

DOCKCROSS=$(PWD)/../dockcross
R2PLUGDIR=/usr/lib/radare2/$(R2_VERSION)

all: root
	$(SUDO) rm -rf control data
	$(MAKE) clean
	mkdir -p data
	cp -rf root/* data
	$(MAKE) control
	$(MAKE) deb

root:
	mkdir -p root/$(R2PLUGDIR)
	cp -f ../../r2ai.$(LIBEXT) root/$(R2PLUGDIR)

purge: clean
	rm -rf root

summary:
	echo $(VERSION)

include deb.mk
