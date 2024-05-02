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

## Features

* Prompt the language model without internet requirements
* Index large codebases or markdown books using a vector database
* Slurp file contents and make actions on that
* Embed the output of an r2 command and resolve questions on the given data
* Define different system-level assistant role
* Set environment variables to provide context to the language model
* Live with repl and batch mode from cli or r2 prompt
* Accessible as an r2lang-python plugin, keeps session state inside radare2
* Scriptable from python, bash, r2pipe, and javascript (r2papi)
* Use different models, dynamically adjust query template
  * Load multiple models and make them talk between them

## Installation

This is optional ans system dependant. but on recent Debian/Ubuntu systems the `pip` tool is no longer working, because it conflicts with the system packages. The best way to do this is with `venv`:

```bash
python -m venv venv
. venv/bin/activate
pip install -r requirements.txt
```

Optionally if you want better indexer for the data install vectordb.

```bash
# on Linux
pip install vectordb2

# on macOS
pip install vectordb2 spacy
python -m spacy download en_core_web_sm
brew install llvm
export PATH=/opt/homebrew/Cellar/llvm/17.0.5/bin/:$PATH
CC=clang CXX=clang++ pip install git+https://github.com/teemupitkanen/mrpt/
```

## r2pm installation

When running installed via r2pm you can execute it like this:

```bash
r2pm -r r2ai
```

Additionally you can get the `r2ai` command inside r2 to run as an rlang plugin by installing the bindings:

```bash
r2pm -i rlang-python
make user-install
```

## Windows

On native Windows follow these instructions (no need to install radare2 or use r2pm), note that you need Python 3.8 or higher:

```cmd
git clone https://github.com/radareorg/r2ai
cd r2ai
set PATH=C:\Users\YOURUSERNAME\Local\Programs\Python\Python39\;%PATH%
python -m pip -r requirements.txt
python -m pip install pyreadline3
python main.py
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

You can interact with r2ai from standalone python, from r2pipe via r2 keeping a global state or using the javascript intrepreter embedded inside `radare2`.

* [conversation.r2.js](examples/conversation.r2.js) - load two models and make them talk to each other

### Development/Testing

Just run `make` .. or well `python main.py`

### TODO

* add "undo" command to drop the last message
* dump / restore conversational states (see -L command)
* Implement `~`, `|` and `>`

### Kudos

The original code of r2ai is based on OpenInterpreter. I want to thanks all the contributors to this project as they made it possible to build r2ai taking their code as source for this.  Kudos to Killian and all the contributors.
