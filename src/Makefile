EXT=$(shell r2 -H R2_LIBEXT)
CFLAGS+=$(shell pkg-config --cflags r_core)
LDFLAGS+=$(shell pkg-config --libs r_core)
R2PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
CFLAGS+=-I. -fPIC

OBJS=r2ai.o
OBJS+=r2ai_anthropic.o
OBJS+=r2ai_gemini.o
OBJS+=r2ai_openai.o
OBJS+=r2ai_openapi.o

all: $(OBJS) r2check
	$(CC) -fPIC -shared -o r2ai.$(EXT) $(OBJS) $(CFLAGS) $(LDFLAGS)
	cp -f r2ai.$(EXT) $(R2PLUGDIR)

clean:
	rm -f *.o *.d

r2check:
	@r2 -qcq --
