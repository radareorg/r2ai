DOTEXE=
# DOTEXE=.exe
DOTLIB=.$(shell r2 -NNH R2_LIBEXT)

R2SYSPLUGDIR=$(shell r2 -NNH R2_LIBR_PLUGINS)
R2USRPLUGDIR=$(shell r2 -NNH R2_USER_PLUGINS)
R2BINDIR=$(shell r2pm -H R2PM_BINDIR)
R2INCDIR=$(shell r2 -NNH R2_INCDIR)/libr
R2LIBDIR=$(shell r2 -NNH R2_LIBDIR)
R2MANDIR=$(shell r2pm -H R2PM_MANDIR)
R2AI_PROMPTSDIR=$(HOME)/.config/r2ai/prompts
ifeq ($(R2MANDIR),)
R2MANDIR=$(shell r2 -NNH R2_PREFIX)/share/man
endif

R2_CFLAGS=$(shell pkg-config --cflags r_core)
R2_LDFLAGS=$(shell pkg-config --libs r_core)
ifeq ($(R2_CFLAGS),)
R2_CFLAGS=$(shell r2 -NNH R2_CFLAGS)
R2_LDFLAGS=$(shell r2 -NNH R2_LDFLAGS)
endif

CFLAGS+=$(R2_CFLAGS)
LDFLAGS+=$(R2_LDFLAGS)
CFLAGS+=-I. -fPIC
CFLAGS+=-Wall
CFLAGS+=-g

AR?=ar

USE_R2_CURL=1
USE_LIBCURL=0

HAVE_LIBCURL=$(shell pkg-config --exists libcurl && echo 1 || echo 0)

CFLAGS+=-DUSE_R2_CURL=$(USE_R2_CURL)
CFLAGS+=-DUSE_LIBCURL=$(USE_LIBCURL)

ifeq ($(USE_LIBCURL),1)
  ifeq ($(HAVE_LIBCURL),1)
    CFLAGS+=$(shell pkg-config --cflags libcurl)
    LDFLAGS+=$(shell pkg-config --libs libcurl)
    CFLAGS+=-DHAVE_LIBCURL=1
  else
    CFLAGS+=-DHAVE_LIBCURL=0
  endif
endif

OBJS=r2ai.o
OBJS+=apikeys.o
OBJS+=async.o
OBJS+=claw.o
OBJS+=llm.o
OBJS+=auto.o
OBJS+=json.o
OBJS+=vdb.o
OBJS+=tools.o
OBJS+=messages.o
OBJS+=anthropic.o
OBJS+=gemini.o
OBJS+=vertex.o
OBJS+=http.o
OBJS+=openai.o
OBJS+=markdown.o
OBJS+=query.o
OBJS+=rawtools.o
OBJS+=wizard.o

all: $(OBJS) r2check
	$(CC) -fPIC -shared -o r2ai$(DOTLIB) $(OBJS) $(CFLAGS) $(LDFLAGS)
	$(AR) rcs libr2ai.a $(OBJS)
	$(CC) -pie -o r2ai$(DOTEXE) $(OBJS) $(CFLAGS) $(LDFLAGS) -lm main.c

# Binary package for r2pm -bi: plugins/, bin/, man/ and prompts/ for this r2 version and platform
# r2pm -H R2PM_* needs a recent r2pm; fall back to uname when missing
R2PM_OS_SH=$(shell r2pm -H R2PM_OS 2>/dev/null)
R2PM_ARCH_SH=$(shell r2pm -H R2PM_ARCH 2>/dev/null)
R2PM_BITS_SH=$(shell r2pm -H R2PM_BITS 2>/dev/null)
ifeq ($(R2PM_OS_SH),)
ifeq ($(shell uname -s),Darwin)
R2PM_OS_SH=darwin
else
R2PM_OS_SH=linux
endif
endif
ifeq ($(R2PM_ARCH_SH),)
ifeq ($(shell uname -m),x86_64)
R2PM_ARCH_SH=x86
else ifneq (,$(filter $(shell uname -m),aarch64 arm64))
R2PM_ARCH_SH=arm
else
R2PM_ARCH_SH=$(shell uname -m)
endif
endif
ifeq ($(R2PM_BITS_SH),)
R2PM_BITS_SH=$(shell getconf LONG_BIT 2>/dev/null || echo 64)
endif
BINDIST_ZIP=r2ai-$(shell r2 -qv)-$(R2PM_OS_SH)-$(R2PM_ARCH_SH)-$(R2PM_BITS_SH).zip

bindist: all
	rm -rf build/bindist ../$(BINDIST_ZIP)
	$(MAKE) user-install R2USRPLUGDIR=$(CURDIR)/build/bindist/plugins R2BINDIR=$(CURDIR)/build/bindist/bin R2MANDIR=$(CURDIR)/build/bindist/man R2AI_PROMPTSDIR=$(CURDIR)/build/bindist/prompts
	cd build/bindist && zip -q -r $(CURDIR)/../$(BINDIST_ZIP) plugins bin man prompts

try: all
	$(MAKE) user-install
	$(MAKE) doc-install

doc-install:
	mkdir -p /tmp/embeds
	cp ../doc/data/quotes.txt /tmp/embeds

vdb.o: vdb_embed.inc.c

fmt format indent:
	clang-format-radare2 *.c http/*.c

user-install: user-uninstall
	mkdir -p $(R2USRPLUGDIR)
	mkdir -p $(R2BINDIR)
	mkdir -p $(R2MANDIR)/man1
	mkdir -p $(R2AI_PROMPTSDIR)
	$(MAKE) user-uninstall
	cp -f r2ai$(DOTLIB) $(R2USRPLUGDIR)/r2ai$(DOTLIB)
	cp -f r2ai$(DOTEXE) $(R2BINDIR)/r2ai$(DOTEXE)
	cp -f r2ai.1 $(R2MANDIR)/man1/r2ai.1
	cp -r ../prompts/* $(R2AI_PROMPTSDIR)/

user-uninstall:
	rm -f $(R2USRPLUGDIR)/r2ai$(DOTLIB)
	rm -f $(R2BINDIR)/r2ai$(DOTEXE)
	rm -f $(R2MANDIR)/man1/r2ai.1

install:
	$(MAKE) uninstall
	mkdir -p $(R2SYSPLUGDIR)
	mkdir -p $(R2BINDIR)
	mkdir -p $(R2LIBDIR)
	mkdir -p $(R2INCDIR)
	cp -f r2ai$(DOTLIB) $(R2SYSPLUGDIR)/r2ai$(DOTLIB)
	cp -f r2ai$(DOTEXE) $(R2BINDIR)/r2ai$(DOTEXE)
	cp -f libr2ai.a $(R2LIBDIR)/libr2ai.a
	cp -f r2ai.h $(R2INCDIR)/r2ai.h

uninstall:
	rm -f $(R2SYSPLUGDIR)/r2ai$(DOTLIB)
	rm -f $(R2BINDIR)/r2ai$(DOTEXE)
	rm -f $(R2LIBDIR)/libr2ai.a
	rm -f $(R2INCDIR)/r2ai.h

r2check:
	@r2 -NN -qcq --
clean:
	rm -f *.o *.d

.PHONY: all bindist try doc-install fmt user-install user-uninstall install uninstall r2check clean test
