[![ci](https://github.com/radareorg/r2ai/actions/workflows/ci.yml/badge.svg)](https://github.com/radareorg/r2ai/actions/workflows/ci.yml)

Integrating language models with radare2.

<p align="center">
  <img src="doc/images/r2clippy.jpg">
</p>

## Components

This repository contains two plugins for radare2:

* **r2ai** - native plugin for radare2
* **decai** - r2js plugin with special focus on decompilation

If you are looking to use radare2 with other agents via MCP:

* **r2mcp** - the [official radare2 mcp](https://github.com/radare2/radare2-mcp)
* **r2copilot** - the mcp with focus on CTF [r2copilot](https://github.com/darallium/r2-copilot)

```
,______  .______ .______  ,___
: __   \ \____  |:      \ : __|
|  \____|/  ____||  _,_  || : |
|   :  \ \   .  ||   :   ||   |
|   |___\ \__:__||___|   ||   |
|___|        :       |___||___|
             *
```

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

The recommended way to install any of the r2ai components is via r2pm:

```console
$ r2pm -Uci r2ai
$ r2pm -Uci decai
```

## Using r2ai

- Adds the **r2ai** command to the radare2 shell: `r2 -qc r2ai`
- You can also run the wrapper in $PATH: `r2pm -r r2ai`

Drop your API keys in environment variables or files in your home:

```console
$ cat ~/.r2ai.anthropic-key 
sk-ant-api03-CENSORED
$ export OPENAI_API_KEY=sk-proj-6rlSPS-zN1v...
```

| AI        | API key                    |
| --------- | -------------------------- |
| OpenAI    | `$HOME/.r2ai.openai-key` |
| Gemini    | `$HOME/.r2ai.gemini-key` |
| Anthropic | `$HOME/.r2ai.anthropic-key` |
| Mistral   | `$HOME/.r2ai.mistral-key` |


## Saving settings

You may customize and save your configuration settings using your OS's default settings file (e.g `~/.radare2rc` on Linux).
For example, the following configuration sets Claude 3.7 by default, with max output tokens to 64000.

```
r2ai -e api=anthropic
r2ai -e model=claude-3-7-sonnet-20250219
r2ai -e max_tokens=64000
```

## Examples

Some practical use cases that can be achieved:

* Enhanced decompilation with `r2ai -d`
* Autoname functions with `r2ai -n`
* Explain function with `r2ai -x`
* Find vulnerabilities with `r2ai -V`

## Documentation

* There's [a chapter](https://book.rada.re/plugins/r2ai.html) in the official r2book
* Cryptax on [lmstudio+gptoss](https://cryptax.medium.com/r2ai-with-lmstudio-and-gpt-oss-08efa5ea2476) blog post
* Malware analysis [with r2ai](https://github.com/cryptax/talks/blob/master/BSidesKristiansand-2025/r2ai.pdf) by Cryptax

## Videos

- https://infosec.exchange/@radareorg/111946255058894583
