# Decai

The AI based Decompiler plugin for radare2

- Written in plain Javascript
- No dependencies than radare2 and curl in PATH
- Uses local ollama by default, but also r2ai-server
- Use services like Anthropic, OpenAI, HF, XAI, DeepSeek, ..

Features

- Auto mode with function calling with ANY model
- Uses the r2 pseudo decompiler by default, supports any other
- Explain purpose and auto-document functions
- Recursive decompilation to inline stubs
- Autoname functions and perform type propagation
- Find vulnerabilities, guide you and write exploits
- Choose any natural language (not just English)
- Choose output programming language (not just C)
- Chain queries to manually fine tune the results
- Customize decompilation prompt at any time

## Installation

Using r2pm: `r2pm -ci decai`

From source: `make user-install`

## Setup

```console
[0x00000000]> decai
Usage: decai (-h) ...
 decai -H         - help setting up r2ai
 decai -d [f1 ..] - decompile given functions
 decai -dr        - decompile function and its called ones (recursive)
 decai -dd [..]   - same as above, but ignoring cache
 decai -dD [query]- decompile current function with given extra query
 decai -e         - display and change eval config vars
 decai -h         - show this help
 decai -i [f] [q] - include given file and query
 decai -n         - suggest better function name
 decai -q [text]  - query language model with given text
 decai -Q [text]  - query on top of the last output
 decai -r         - change role prompt (same as: decai -e prompt)
 decai -R         - reset role prompt to default prompt
 decai -s         - function signature
 decai -v         - show local variables
 decai -V         - find vulnerabilities
 decai -x         - eXplain current function
```

Configuration options:

```console
[0x00000000]> decai -e
decai -e api=ollama
decai -e host=http://localhost
decai -e port=11434
decai -e prompt=Rewrite this function and respond ONLY with code, NO explanations, NO markdown, Change 'goto' into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and strings from comments like 'string:'
decai -e ctxfile=
decai -e cmds=pdc
decai -e cache=false
decai -e lang=C
decai -e hlang=English
decai -e debug=false
decai -e model=
decai -e maxinputtokens=-1
```

## Running decai

Decai is used from `r2` (e.g `r2 ./mybinary`). Get help with `decai -h`:

```
[0x00406cac]> decai -h
Usage: decai (-h) ...
 decai -H         - help setting up r2ai
 decai -a [query] - solve query with auto mode
 decai -d [f1 ..] - decompile given functions
 decai -dr        - decompile function and its called ones (recursive)
 decai -dd [..]   - same as above, but ignoring cache
 decai -dD [query]- decompile current function with given extra query
 ...
```

List configuration variables with `decai -e`:

```
[0x00406cac]> decai -e
decai -e api=ollama
decai -e host=http://localhost
decai -e port=11434
decai -e prompt=Rewrite this function and respond ONLY with code, NO explanations, NO markdown, Change 'goto' into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and strings from comments like 'string:'
decai -e ctxfile=
...
```

List possible APIs to discuss with AI: `decai -e api=?`:

```
[0x00406cac]> decai -e api=?
r2ai
claude
openapi
...
```

### Example using a local model and ollama

For example, if Ollama serves model codegeex4:latest (`ollama ls`), set decai API as `ollama` and model `codegeex4:latest`.

```
[0x00002d30]> decai -e api=ollama
[0x00002d30]> decai -e model=codegeex4:latest
[0x00002d30]> decai -q Explain what forkpty does in 2 lines
The `forkpty` function creates a new process with a pseudo-terminal, allowing the parent to interact with the child via standard input/output/err and controlling its terminal.
```


## Examples

See
[https://github.com/radareorg/r2ai-examples](https://github.com/radareorg/r2ai-examples)

```c
$ cat stack-overflow/bug.c 

#include <string.h>

int main(int argc, char **argv) {
	char buf[32];
	strcpy (buf, argv[1]);
	return 0;
}
```

```c
$ r2 buffer-overflow/a.out
[0x100003f58]> decai -d
int main(int argc, char **argv, char **envp) {
    char buffer[32];
    int result = 0;
    
    if (argc > 1 && argv[1] != NULL) {
        strcpy(buffer, argv[1]);
    }
    
    return result;
}
```

### Example using a local Mistral model and r2ai-server

For example, assuming we have a *local* Mistral AI server running on port 8080 with `r2ai-server`, we can decompile a given function with `decai -d`.
The server shows it received the question:

```
GET
CUSTOM
RUNLINE: -R
127.0.0.1 - - [13/Dec/2024 10:40:49] "GET /cmd/-R HTTP/1.1" 200 -
GET
CUSTOM
RUNLINE: -i /tmp/.pdc.txt Rewrite this function and respond ONLY with code, NO explanations, NO markdown, Change goto into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and and strings from comments like string:. Transform this pseudocode into C
```

### Example using a Mistral API key 

Put the API key in `~/.r2ai.mistral-key`.

```
[0x000010d0]> decai -e api=mistral
[0x000010d0]> decai -d main
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv, char **envp) {
    char password[40];
    char input[40];
...
```


### Example with ChatGPT 4

```
[0x00406cac]> decai -e api=openai
[0x00406cac]> decai -d
#include <stdio.h>
#include <unistd.h>

void daemonize() {
    daemon(1, 0);
}
...
```



