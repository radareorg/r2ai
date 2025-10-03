SHELL=/bin/bash

PROVIDER=ollama
MODELS=granite3-dense:8b mannix/jan-nano:latest yi-coder:latest qwen3:latest deepseek-coder-v2:latest hhao/qwen2.5-coder-tools:latest qwen2.5-coder:latest
MODELS=gemma3:1b
LANGS=Dart Perl Ruby Javascript PHP C
BINARIES=files/complex1 files/complex2 files/complex3
#MODELS=gpt-4o
#PROVIDER=openai

all:
	mkdir -p tmp
	for b in $(BINARIES) ; do \
		for a in $(MODELS) ; do \
			for l in $(LANGS) ; do \
				echo "$$b $$a $$l"; \
				PLAIN=1 ./run.sh "echo \"decai -e model=$$a;decai -e lang=$$l;decai -e api=${PROVIDER};s 0x100000924;af;decai -d\" | r2 -q $$b" 2> /dev/null | tee tmp/$${b##*/}_$${a//\//_}_$${l}.txt ; \
			done ; \
		done ; \
	done

compile: $(BINARIES)

files/complex1: files/complex1.c
	gcc -o $@ $<

files/complex2: files/complex2.c
	gcc -o $@ $<

files/complex3: files/complex3.c
	gcc -o $@ $<

lmstudio:
	for b in $(BINARIES) ; do \
		for a in $(MODELS) ; do \
			for l in $(LANGS) ; do \
				PLAIN=1 ./run.sh "echo \"decai -e model=$$a;decai -e lang=$$l;s 0x100000924;af;decai -d\" | r2 -q $$b" > $${b##*/}_$${a//\//_}_$${l}.txt ; \
			done ; \
		done ; \
	done
