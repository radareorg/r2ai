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
			echo "$$b $$a"; \
			./run.sh $$b $$a ${PROVIDER} ${LANGS} > tmp/$${b##*/}_$${a//\//_}.html 2> /dev/null ; \
		done ; \
	done

.PHONY: run index evaluate

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
			./run.sh $$b $$a lmstudio ${LANGS} > $${b##*/}_$${a//\//_}.html ; \
		done ; \
	done

clean:
	rm -rf tmp
