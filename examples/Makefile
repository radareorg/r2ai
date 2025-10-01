SHELL=/bin/bash

MODELS=gpt-oss:20b gemma3:4b
LANGS=Dart Perl Ruby Javascript PHP C

all:
	for a in ${MODELS} ; do \
		declare -a ARGS; \
		for l in ${LANGS} ; do \
			ARGS+=("echo \"decai -e model=$$a;decai -e lang=$$l;s 0x100000924;af;decai -d\" | r2 -q /bin/ls"); \
		done ; \
		./benchmark_to_html.sh "$${ARGS[@]}" > $$a.html ; done
