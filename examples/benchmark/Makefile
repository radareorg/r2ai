SHELL=/bin/bash

MODELS=gpt-oss:20b gemma3:4b gemma3:12b
MODELS+=granite3-dense:8b mannix/jan-nano:latest yi-coder:latest qwen3:latest deepseek-coder-v2:latest hhao/qwen2.5-coder-tools:latest qwen2.5-coder:latest
MODELS=granite3-dense:8b mannix/jan-nano:latest yi-coder:latest qwen3:latest deepseek-coder-v2:latest hhao/qwen2.5-coder-tools:latest qwen2.5-coder:latest
LANGS=Dart Perl Ruby Javascript PHP C

all:
	for a in ${MODELS} ; do \
		declare -a ARGS; \
		for l in ${LANGS} ; do \
			ARGS+=("echo \"decai -e model=$$a;decai -e lang=$$l;s 0x100000924;af;decai -d\" | r2 -q /bin/ls"); \
		done ; \
		./run.sh "$${ARGS[@]}" > ${a//\//_}.html ; done
