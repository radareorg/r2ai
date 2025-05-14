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
  <img src="doc/images/r2clippy.jpg">
</p>

## Components

R2AI repository contains four different projects:

Recommended plugins:

* **r2ai-plugin** (`src/` directory)
  * Native plugin written in C
  * adds r2ai command inside r2
* **decai** (r2js plugin focus on decompilation)
  * adds 'decai' command to the r2 shell
  * talks to local or remote services with curl
  * focus on decompilation

Deprecated implementations:

* **r2ai-python** cli tool (`py/` directory)
  * r2-like repl using r2pipe to comunicate with r2
  * supports auto solving mode
  * client and server openapi protocol
  * download and manage models from huggingface
* **r2ai-server**
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

### Radare2 Package Manager

The recommended way to install any of the r2ai components is via r2pm:

You can find all the packages with `r2pm -s r2ai`:

```console
$ r2pm -s r2ai
r2ai-py             run a local language model integrated with radare2
r2ai-py-plugin      r2ai plugin for radare2
r2ai-plugin         r2ai plugin rewritten in plain C
r2ai-server         start a language model webserver in local
decai               r2ai r2js subproject with focus on LLM decompilation for radare2
$
```

### From sources

Running `make` on the root directory will instruct you where the sub-projects are, just run the `install`/`user-install` targets in there.

```console
$ make
Usage: Run 'make' in the following subdirectories instead
src/    - Modern C rewrite in form of a native r2 plugin
py/     - The old Python cli and r2 plugin
decai/  - r2js plugin with focus on decompiling
server/ - shellscript to easily run llamacpp and other
$
```

## Running r2ai

### Launch r2ai

- The r2ai-plugin adds the **r2ai** command to the radare2 shell: `r2 -qc r2ai-r`
- If you installed via r2pm, you can execute it like this: `r2pm -r r2ai`
- Otherwise, `./r2ai.sh [/absolute/path/to/binary]`

If you have an **API key**, put it in the adequate file:

| AI        | API key                    |
| --------- | -------------------------- |
| OpenAI    | `$HOME/.r2ai.openai-key` |
| Gemini    | `$HOME/.r2ai.gemini-key` |
| Anthropic | `$HOME/.r2ai.anthropic-key` |
| Mistral   | `$HOME/.r2ai.mistral-key` |
...

Example using an Anthropic API key:

```
$ cat ~/.r2ai.anthropic-key 
sk-ant-api03-CENSORED
```

## Videos

- https://infosec.exchange/@radareorg/111946255058894583
