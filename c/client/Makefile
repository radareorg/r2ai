EXT=$(shell r2 -H R2_LIBEXT)
R2PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)

all:
	$(CC) -fPIC -shared -o r2ai-client.$(EXT) client.c $(shell pkg-config --cflags --libs r_core)
	cp -f r2ai-client.$(EXT) $(R2PLUGDIR)
