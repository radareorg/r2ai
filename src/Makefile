EXT=$(shell r2 -H R2_LIBEXT)
CFLAGS+=$(shell pkg-config --cflags r_core)
LDFLAGS+=$(shell pkg-config --libs r_core)
R2PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
CFLAGS+=-I. -fPIC
CFLAGS+=-Wall
CFLAGS+=-g

OBJS=r2ai.o
OBJS+=auto.o
OBJS+=vdb.o
OBJS+=anthropic.o
OBJS+=gemini.o
OBJS+=openai.o
OBJS+=openapi.o
OBJS+=ollama.o
OBJS+=xai.o

all: $(OBJS) r2check
	$(CC) -fPIC -shared -o r2ai.$(EXT) $(OBJS) $(CFLAGS) $(LDFLAGS)

try: all
	$(MAKE) user-install
	$(MAKE) doc-install

doc-install:
	mkdir -p /tmp/embeds
	cp ../doc/data/quotes.txt /tmp/embeds

vdb.o: vdb_embed.inc.c

install user-install:
	mkdir -p $(R2PLUGDIR)
	rm -f $(R2PLUGDIR)/r2ai.$(EXT)
	cp -f r2ai.$(EXT) $(R2PLUGDIR)

uninstall user-uninstall:
	cp -f $(R2PLUGDIR)/r2ai.$(EXT)

r2check:
	@r2 -qcq --
clean:
	rm -f *.o *.d
