```
,______  .______ .______  ,___
: __   \ \____  |:      \ : __|
|  \____|/  ____||  _,_  || : |
|   :  \ \   .  ||   :   ||   |
|   |___\ \__:__||___|   ||   |
|___|        :       |___||___|
             *       --pancake
```

[![ci](https://github.com/radareorg/r2ai/actions/workflows/ci.yml/badge.svg)](https://github.com/radareorg/r2ai/actions/workflows/ci.yml)

Run a language model in local, without internet, to entertain you or help answering questions about radare2 or reverse engineering in general. Note that models used by r2ai are pulled from external sources which may behave different or respond unrealible information. That's why there's an ongoing effort into improving the post-finetuning using memgpt-like techniques which can't get better without your help!

<p align="center">
  <img src="doc/r2clippy.jpg">
</p>

## Components

R2AI is structured into four independent components:

* r2ai (wip r2ai-native rewrite in C)
  * r2-like repl using r2pipe to comunicate with r2
  * supports auto solving mode
  * client and server openapi protocol
  * download and manage models from huggingface
* decai
  * lightweight r2js plugin
  * focus on decompilation
  * talks to r2ai, r2ai-server, openai, anthropic or ollama
* r2ai-plugin
  * requires r2lang-python
  * adds r2ai command inside r2
  * not recommended because of python versions pain
* r2ai-server
  * list and select models downloaded from r2ai
  * simple cli tool to start local openapi webservers
  * supports llamafile, llamacpp, r2ai-w and kobaldcpp

## Features

* Support Auto mode (see below) to solve tasks using function calling
* Use local and remote language models (llama, ollama, openai, anthropic, ..)
* Support OpenAI, Anthropic, Bedrock
* Index large codebases or markdown books using a vector database
* Slurp file and perform actions on that
* Embed the output of an r2 command and resolve questions on the given data
* Define different system-level assistant role
* Set environment variables to provide context to the language model
* Live with repl and batch mode from cli or r2 prompt
* Accessible as an r2lang-python plugin, keeps session state inside radare2
* Scriptable from python, bash, r2pipe, and javascript (r2papi)
* Use different models, dynamically adjust query template
  * Load multiple models and make them talk between them

## Installation

Running `make` will setup a python virtual environment in the current directory installing all the necessary dependencies and will get into a shell to run r2ai.

The installation is now splitted into two different targets:

* `make install` will place a symlink in `$BINDIR/r2ai`
* `make install-plugin` will install the native r2 plugin into your home
* `make install-decai` will install the decai r2js decompiler plugin
* `make install-server` will install the decai r2js decompiler plugin

## Running

When installed via r2pm you can execute it like this:

```bash
r2pm -r r2ai
```

Additionally you can get the `r2ai` command inside r2 to run as an rlang plugin by installing the bindings:

```bash
r2pm -i rlang-python
make user-install
```

After this you should get the `r2ai` command inside the radare2 shell. Set the `R2_DEBUG=1` environment to see the reasons why the plugin is not loaded if it's not there.

## Windows

On Windows you may follow the same instructions, just ensure you have the right python environment ready and create the venv to use

```cmd
git clone https://github.com/radareorg/r2ai
cd r2ai
set PATH=C:\Users\YOURUSERNAME\Local\Programs\Python\Python39\;%PATH%
python3 -m pip install .
python3 main.py
```

## Usage

There are 4 different ways to run `r2ai`:

* Standalone and interactive: `r2pm -r r2ai` or `python main.py`
* Batch mode: `r2ai '-r act as a calculator' '3+3=?'`
* As an r2 plugin: `r2 -i main.py /bin/ls`
* From radare2 (requires `r2pm -ci rlang-python`): `r2 -c 'r2ai -h'`
* Using r2pipe: `#!pipe python main.py`
  * Define a macro command: `'$r2ai=#!pipe python main.py`

## Auto mode

When using OpenAI, Claude or any of the Functionary local models you can use the auto mode which permits the language model to execute r2 commands, analyze the output in loop and in a loop until it is resolved. Here's a sample session to achieve that:

* Video https://infosec.exchange/@radareorg/111946255058894583

```bash
$ . env/bin/activate
(env)$ r2 /bin/ls
[0x00000000]> '$r2ai=#!pipe python main.py
[0x00000000]> $r2ai '-m openai:gpt-4'
[0x00000000]> $r2ai "' list the imports for this program"
[0x00000000]> $r2ai "' draw me a donut"
[0x00000000]> $r2ai "' decompile current function and explain it"
```

## Examples

You can interact with r2ai from standalone python, from r2pipe via r2 keeping a global state or using the javascript interpreter embedded inside `radare2`.

* [conversation.r2.js](examples/conversation.r2.js) - load two models and make them talk to each other

### Development/Testing

Just run `make` .. or well `python3 main.py`

### TODO

* add "undo" command to drop the last message
* dump / restore conversational states (see -L command)
* Implement `~`, `|` and `>` and other r2shell features
