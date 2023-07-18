all: node_modules
	tsc r2ai.ts
	gcc hello.c -o hello
	# r2 -c 'af' -c '$$ai=. r2ai.js' -i r2ai.js hello
	r2 -c 'af' -c '$$ai=. r2ai.js' hello

node_modules:
	mkdir -p node_modules
	npm i
