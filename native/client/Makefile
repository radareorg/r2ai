EXT=$(shell r2 -H R2_LIBEXT)
CFLAGS+=$(shell pkg-config --cflags r_core)
LDFLAGS+=$(shell pkg-config --libs r_core)
R2PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)

all: r2check
	$(CC) -fPIC -shared -o r2ai-client.$(EXT) client.c $(CFLAGS) $(LDFLAGS)
	cp -f r2ai-client.$(EXT) $(R2PLUGDIR)

r2check:
	@r2 -qcq --
