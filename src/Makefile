DOTEXE=
# DOTEXE=.exe
DOTLIB=.$(shell r2 -H R2_LIBEXT)

R2SYSPLUGDIR=$(shell r2 -H R2_LIBR_PLUGINS)
R2USRPLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
R2BINDIR=$(shell r2pm -H R2PM_BINDIR)

R2_CFLAGS=$(shell pkg-config --cflags r_core)
R2_LDFLAGS=$(shell pkg-config --libs r_core)
ifeq ($(R2_CFLAGS),)
R2_CFLAGS=-I../third_party/radare2-mcp/src -I/usr/local/include/libr
R2_LDFLAGS=-L/usr/local/lib -lr_core -lr_util -lr_cons -lr_io -lr_asm -lr_debug -lr_flag -lr_sign -lr_search -lr_syscall -lr_bp -lr_reg -lr_config -lr_lang -lr_anal -lr_parse -lr_hash -lr_crypto -lr_fs -lr_magic -lr_socket -lr_cons -lr_flag -lr_util -lr_reg -lr_syscall -lr_search -lr_sign -lr_crypto -lr_hash -lr_debug -lr_main -lr_session -lr_magic -lr_io -lr_socket -lr_fs -lr_lang -lr_anal -lr_parse -lr_egg -lr_debug -lr_bin -lr_config -lr_cons -lr_io -lr_asm -lr_flag -lr_core -lm
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
OBJS+=auto.o
OBJS+=vdb.o
OBJS+=tools.o
OBJS+=messages.o
OBJS+=anthropic.o
OBJS+=r2ai_http.o
OBJS+=openai.o
OBJS+=markdown.o

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
	clang-format-radare2 *.c

user-install: user-uninstall
	mkdir -p $(R2USRPLUGDIR)
	mkdir -p $(R2BINDIR)
	$(MAKE) user-uninstall
	cp -f r2ai$(DOTLIB) $(R2USRPLUGDIR)/r2ai$(DOTLIB)
	cp -f r2ai$(DOTEXE) $(R2BINDIR)/r2ai$(DOTEXE)

user-uninstall:
	rm -f $(R2USRPLUGDIR)/r2ai$(DOTLIB)
	rm -f $(R2BINDIR)/r2ai$(DOTEXE)

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
	@r2 -qcq --
clean:
	rm -f *.o *.d
