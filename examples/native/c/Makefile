CFLAGS+=-I/usr/local/include
LDFLAGS+=/usr/local/lib/libllama.a

ifeq ($(shell uname),Darwin)
LDFLAGS+=-DGGML_USE_METAL
LDFLAGS+=-lc++
LDFLAGS+=-lcblas
LDFLAGS+=-framework Foundation -framework Metal -framework MetalKit
LDFLAGS+=-framework Accelerate
endif

all:
	$(CC) $(CFLAGS) main.c $(LDFLAGS)
