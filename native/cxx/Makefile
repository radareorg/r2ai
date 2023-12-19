CFLAGS+=-I/usr/local/include
LDFLAGS+=/usr/local/lib/libllama.a

ifeq ($(shell uname),Darwin)
LDFLAGS+=-DGGML_USE_METAL
LDFLAGS+=-lcblas
LDFLAGS+=-framework Foundation -framework Metal -framework MetalKit
LDFLAGS+=-framework Accelerate
endif
R2FLAGS=$(shell pkg-config --cflags --libs r_core)
SOEXT=$(shell r2 -H R2_LIBEXT)
R2_USER_PLUGINS=$(shell r2 -H R2_USER_PLUGINS)

all:
	g++ -o r2ai.$(SOEXT) -std=c++11 $(CFLAGS) $(LDFLAGS) $(R2FLAGS) -DR2AI=1 -fPIC -shared r2ai.cpp main.cpp
	mkdir -p $(R2_USER_PLUGINS)
	cp -f r2ai.$(SOEXT) $(R2_USER_PLUGINS)
	g++ -std=c++11 $(CFLAGS) $(LDFLAGS) main.cpp

run:
	./a.out -n -1 --color -r "User:" --in-prefix " " -i -p \
"User: Hi\
AI: Hello. I am an AI chatbot. Would you like to talk?\
User: Sure!\
AI: What would you like to talk about?\
User:"

run2:
	./a.out --color -r "[INST]" --in-suffix "[/INST]" -i -p \
"<s>[INST]Hello, what is your name?[/INST]\
My name is r2ai, a language model for radare2 which responds paragraphs</s>\
<s>[INST]who is the author of radare2?[/INST]\
He is pancake, aka Sergi Alvarez</s>"

s:
	./a.out --color -r "[INST]" --in-suffix "[/INST]" --in-prefix "<s>[INST]" -i -p \
"<s>[INST]Hello, what is your name?[/INST]\
My name is r2ai, a language model for radare2 which responds paragraphs</s>\
<s>[INST]who is the author of radare2?[/INST]\
He is pancake, aka Sergi Alvarez</s>"

z:
	./a.out -p \
"<s>[INST]Hello, what is your name?[/INST]\
My name is r2ai, a language model for radare2 which responds paragraphs</s>\
<s>[INST]who is the author of radare2?[/INST]\
He is pancake, aka Sergi Alvarez</s>"
