```
,______  .______ .______  ,___
: __   \ \____  |:      \ : __|
|  \____|/  ____||  _,_  || : |
|   :  \ \   .  ||   :   ||   |
|   |___\ \__:__||___|   ||   |
|___|        :       |___||___|
             *
```

[![ci](https://github.com/radareorg/r2ai/actions/workflows/ci.yml/badge.svg)](https://github.com/radareorg/r2ai/actions/workflows/ci.yml)

Run a language model to entertain you or help answering questions about radare2 or reverse engineering in general. The language model may be local (running without Internet on your host) or remote (e.g if you have an API key). Note that models used by r2ai are pulled from external sources which may behave different or respond unreliable information. That's why there's an ongoing effort into improving the post-finetuning using memgpt-like techniques which can't get better without your help!

<p align="center">
  <img src="doc/r2clippy.jpg">
</p>

## Components

R2AI is structured into four independent components:

* r2ai (python cli tool)
  * r2-like repl using r2pipe to comunicate with r2
  * supports auto solving mode
  * client and server openapi protocol
  * download and manage models from huggingface
* decai (r2js plugin focus on decompilation)
  * adds 'decai' command to the r2 shell
  * talks to local or remote services with curl
  * focus on decompilation
* *r2ai-plugin*
  * Native plugin written in C
  * adds r2ai command inside r2
* r2ai-server
  * favour *ollama* instead
  * list and select models downloaded from r2ai
  * simple cli tool to start local openapi webservers
  * supports llamafile, llamacpp, r2ai-w and kobaldcpp
  

## Features

* Support Auto mode to solve tasks using function calling
* Use local and remote language models (llama, ollama, openai, anthropic, ..)
* Support OpenAI, Anthropic, Bedrock
* Index large codebases or markdown books using a vector database
* Slurp file and perform actions on that
* Embed the output of an r2 command and resolve questions on the given data
* Define different system-level assistant role
* Set environment variables to provide context to the language model
* Live with repl and batch mode from cli or r2 prompt
* Scriptable via r2pipe
* Use different models, dynamically adjust query template
* Load multiple models and make them talk between them

## Installation

### From r2pm

Install the various components via `r2pm`:

- `r2pm -ci r2ai`
- `r2pm -ci r2ai-plugin`
- `r2pm -ci decai`
- `r2pm -ci r2ai-server`

### From sources

Running `make` will setup a python virtual environment in the current directory installing all the necessary dependencies and will get into a shell to run r2ai.

The installation is now splitted into two different targets:

* `make install` will place a symlink in `$BINDIR/r2ai`
* `make install-decai` will install the decai r2js decompiler plugin
* `make install-server` will install the r2ai-server

### Windows

On Windows you may follow the same instructions, just ensure you have the right python environment ready and create the venv to use

```cmd
git clone https://github.com/radareorg/r2ai
cd r2ai
set PATH=C:\Users\YOURUSERNAME\Local\Programs\Python\Python39\;%PATH%
python3 -m pip install .
python3 main.py
```

## Running r2ai

### Launch r2ai

- If you installed via r2pm, you can execute it like this: `r2pm -r r2ai`
- Otherwise, `./r2ai.sh [/absolute/path/to/binary]`

If you have an **API key**, put it in the adequate file:

| AI        | API key                    |
| --------- | -------------------------- |
| OpenAI    | `$HOME/.r2ai.openai-key` |
| Gemini    | `$HOME/.r2ai.gemini-key` |
| Anthropic | `$HOME/.r2ai.anthropic-key` |
| Mistral   | `$HOME/.r2ai.mistral-key` |

Example using an Anthropic API key:

```
$ cat ~/.r2ai.anthropic-key 
sk-ant-api03-CENSORED
```

### Selecting the model

- List all downloaded models: `-m`
- Get a short list of models: `-MM`
- Help: `-h`

**Example selecting a remote models:**

```
[r2ai:0x00006aa0]> -m anthropic:claude-3-5-sonnet-20241022
[r2ai:0x00006aa0]> -m openai:gpt-4
```

**Example downloading a free local AI: Mistral 7B v0.2:**

Launch r2ai, select the model and ask a question. If the model isn't downloaded yet, r2ai will ask you which precise version to download.

```
[r2ai:0x00006aa0]> -m TheBloke/Mistral-7B-Instruct-v0.2-GGUF
```

Then ask your question, and r2ai will automatically download if needed:

```
[r2ai:0x00006aa0]> give me a short algorithm to test prime numbers
Select TheBloke/Mistral-7B-Instruct-v0.2-GGUF model. See -M and -m flags
[?] Quality (smaller is faster): 
 > Small | Size: 2.9 GB, Estimated RAM usage: 5.4 GB
   Medium | Size: 3.9 GB, Estimated RAM usage: 6.4 GB
   Large | Size: 7.2 GB, Estimated RAM usage: 9.7 GB
   See More

[?] Quality (smaller is faster): 
 > mistral-7b-instruct-v0.2.Q2_K.gguf | Size: 2.9 GB, Estimated RAM usage: 5.4 GB
   mistral-7b-instruct-v0.2.Q3_K_L.gguf | Size: 3.6 GB, Estimated RAM usage: 6.1 GB
   mistral-7b-instruct-v0.2.Q3_K_M.gguf | Size: 3.3 GB, Estimated RAM usage: 5.8 GB
   mistral-7b-instruct-v0.2.Q3_K_S.gguf | Size: 2.9 GB, Estimated RAM usage: 5.4 GB
   mistral-7b-instruct-v0.2.Q4_0.gguf | Size: 3.8 GB, Estimated RAM usage: 6.3 GB
   mistral-7b-instruct-v0.2.Q4_K_M.gguf | Size: 4.1 GB, Estimated RAM usage: 6.6 GB
   mistral-7b-instruct-v0.2.Q4_K_S.gguf | Size: 3.9 GB, Estimated RAM usage: 6.4 GB
   mistral-7b-instruct-v0.2.Q5_0.gguf | Size: 4.7 GB, Estimated RAM usage: 7.2 GB
   mistral-7b-instruct-v0.2.Q5_K_M.gguf | Size: 4.8 GB, Estimated RAM usage: 7.3 GB
   mistral-7b-instruct-v0.2.Q5_K_S.gguf | Size: 4.7 GB, Estimated RAM usage: 7.2 GB
   mistral-7b-instruct-v0.2.Q6_K.gguf | Size: 5.5 GB, Estimated RAM usage: 8.0 GB
   mistral-7b-instruct-v0.2.Q8_0.gguf | Size: 7.2 GB, Estimated RAM usage: 9.7 GB

[?] Use this model by default? ~/.r2ai.model: 
 > Yes
   No

[?] Download to ~/.local/share/r2ai/models? (Y/n): Y
```

### Standard/Auto mode

The standard mode is invoked by directly asking the question.
For the Auto mode, the question **must be prefixed** by `' ` (quote + space). The AI may instruct r2ai to run various commands. Those commands are run on *your host*, so you will be asked to review them before they run.

Example in "standard" mode:

```
[r2ai:0x00006aa0]> compute 4+5
4 + 5 = 9
[r2ai:0x00006aa0]> draw me a pancake in ASCII art
Sure, here's a simple ASCII pancake:

  _____  
 (     )
 (     )
  -----
```

Example in auto mode:

```
[r2ai:0x00006aa0]>' Decompile the main
[..]
r2ai is going to execute the following command on the host
Want to edit? (ENTER to validate) pdf @ fcn.000015d0
This command will execute on this host: pdf @ fcn.000015d0. Agree? (y/N) y
```

If you wish to edit the command, you can do it inline for short one line commands, or an editor will pop up.




## Running r2ai-server

- Get usage: `r2pm -r r2ai-server`
- List available servers: `r2pm -r r2ai-server -l`
- List available models: `r2pm -r r2ai-server -m`

On Linux, models are stored in `~/.r2ai.models/`. File `~/.r2ai.model` lists the default model and other models.

**Example launching a local Mistral AI server:**

```
$ r2pm -r r2ai-server -l r2ai -m mistral-7b-instruct-v0.2.Q2_K
[12/13/24 10:35:22] INFO     r2ai.server - INFO - [R2AI] Serving at port 8080                               web.py:336
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




## Videos

- https://infosec.exchange/@radareorg/111946255058894583


## Development/Testing

Just run `make` 


## TODO

* add "undo" command to drop the last message
* dump / restore conversational states (see -L command)
* Implement `~`, `|` and `>` and other r2shell features

