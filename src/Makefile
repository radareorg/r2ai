DOTEXE=
# DOTEXE=.exe
DOTLIB=.$(shell r2 -NNH R2_LIBEXT)

R2SYSPLUGDIR=$(shell r2 -NNH R2_LIBR_PLUGINS)
R2USRPLUGDIR=$(shell r2 -NNH R2_USER_PLUGINS)
R2BINDIR=$(shell r2pm -H R2PM_BINDIR)
R2MANDIR=$(shell r2pm -H R2PM_MANDIR)

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
OBJS+=llm.o
OBJS+=auto.o
OBJS+=json.o
OBJS+=vdb.o
OBJS+=tools.o
OBJS+=messages.o
OBJS+=anthropic.o
OBJS+=http.o
OBJS+=openai.o
OBJS+=markdown.o
OBJS+=query.o
OBJS+=rawtools.o

all: $(OBJS) r2check
	$(CC) -fPIC -shared -o r2ai$(DOTLIB) $(OBJS) $(CFLAGS) $(LDFLAGS)
	$(CC) -pie -o r2ai$(DOTEXE) $(OBJS) $(CFLAGS) $(LDFLAGS) -lm main.c

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
	mkdir -p $(HOME)/.config/r2ai/prompts
	$(MAKE) user-uninstall
	cp -f r2ai$(DOTLIB) $(R2USRPLUGDIR)/r2ai$(DOTLIB)
	cp -f r2ai$(DOTEXE) $(R2BINDIR)/r2ai$(DOTEXE)
	cp -f r2ai.1 $(R2MANDIR)/man1/r2ai.1
	cp -r ../prompts/* $(HOME)/.config/r2ai/prompts/

user-uninstall:
	rm -f $(R2USRPLUGDIR)/r2ai$(DOTLIB)
	rm -f $(R2BINDIR)/r2ai$(DOTEXE)
	rm -f $(R2MANDIR)/man1/r2ai.1

install:
	$(MAKE) uninstall
	mkdir -p $(R2USRPLUGDIR)
	mkdir -p $(R2BINDIR)
	cp -f r2ai$(DOTLIB) $(R2SYSPLUGDIR)/r2ai$(DOTLIB)
	cp -f r2ai$(DOTEXE) $(R2BINDIR)/r2ai$(DOTEXE)

uninstall:
	rm -f $(R2SYSPLUGDIR)/r2ai$(DOTLIB)
	rm -f $(R2BINDIR)/r2ai$(DOTEXE)

r2check:
	@r2 -NN -qcq --
clean:
	rm -f *.o *.d
