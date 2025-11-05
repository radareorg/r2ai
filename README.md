# R2AI - Augmented reversing with LLM for radare2

```console
         ╭─────────────────────────────────╮
         │ ,______  .______ .______  ,___  │
 ╭──╮    │ : __   \ \____  |:      \ : __| │
 │ _│_   │ |  \____|/  ____||  _,_  || : | │
 │ O O  <  |   :  \ \   .  ||   :   ||   | │
 │  │╷   │ |   |___\ \__:__||___|   ||   | │
 │  ││   │ |___|        :       |___||___| │
 │ ─╯│   ╰─────────────────────────────────╯
 ╰───╯
```

[![ci](https://github.com/radareorg/r2ai/actions/workflows/ci.yml/badge.svg)](https://github.com/radareorg/r2ai/actions/workflows/ci.yml)
[![radare2](https://img.shields.io/badge/radare2-6.0.4-green)](https://github.com/radareorg/radare2)

## Components

This repository contains two plugins for radare2:

* **r2ai** - native [AI plugin](./src/README.md) for radare2
* **decai** - r2js plugin with special [focus on decompilation](./decai/README.md)

If you are looking to use radare2 with other agents via MCP:

* **r2mcp** - the [official radare2 mcp](https://github.com/radare2/radare2-mcp)
* **r2copilot** - the mcp with focus on CTF [r2copilot](https://github.com/darallium/r2-copilot)

## Features

* Configure different roles and customize prompts
* Scriptable via r2pipe via the r2ai command
* Live with repl and batch mode from cli or r2 prompt
* Support Automatic (ReAct) mode to solve tasks using function calling
* Use local and remote language models (ollama, openai, grok, anthropic, ..)
* RAG markdown, code or textfiles using its native vector database
* Embed the output of an r2 command and resolve questions on the given data

## User defined Prompts

```console
[0x00000000]> r2ai -q
explain: Explain the current function -
devices: Find and explain devices used -
libs: Group imports by Libraries -
varnames: Better variable names -
autoname: Automatically suggest a better name for this function -
vulns: Find vulnerabilities or bugs in the current function -
signature: Suggest an improved function signature -
dlopen: List libraries loaded with dlopen - Some libraries are loaded
decompile: Augmented decompilation based on LLM -
[0x00000000]>
```

## Installation

The recommended way to install any of the r2ai components is via r2pm:

```console
$ r2pm -Uci r2ai
$ r2pm -Uci decai
```

## Using r2ai

- Adds the **r2ai** command to the radare2 shell: `r2 -qc r2ai`
- You can also run the wrapper in $PATH: `r2pm -r r2ai`

Drop your API keys in environment variables or use the configuration file:

```console
$ export ANTHROPIC_API_KEY=sk-ant-api03-CENSORED
$ export OPENAI_API_KEY=sk-proj-6rlSPS-zN1v...
```

Or edit the api keys file `~/.config/r2ai/apikeys.txt` run:

```console
$ r2ai -K
```

## Saving settings

You may customize and save your configuration settings using your OS's default settings file (e.g `~/.radare2rc` on Linux).
For example, the following configuration sets Claude 3.7 by default, with max output tokens to 64000.


```console
$ r2ai -E
```

then you can type the commands you want to run when the r2ai plugin is loaded:

```console
r2ai -e api=anthropic
r2ai -e model=claude-3-7-sonnet-20250219
r2ai -e max_tokens=64000
```

## Further Reading

* There's [a chapter](https://book.rada.re/plugins/r2ai.html) in the official r2book
* Cryptax on [lmstudio+gptoss](https://cryptax.medium.com/r2ai-with-lmstudio-and-gpt-oss-08efa5ea2476) blog post
* Malware analysis [with r2ai](https://arxiv.org/pdf/2504.07574) by Cryptax and Daniel Nakov
* Analysis of [Linux/Trigona ransomware](https://cryptax.medium.com/linux-trigona-analysis-with-r2ai-3e2bd1815e52),  [Linux/Prometei botnet](https://cryptax.medium.com/reversing-a-prometei-botnet-binary-with-r2-and-ai-part-one-3cdb3dc6ffab) and [W32/SkyAI](https://cryptax.medium.com/w32-skyai-uses-ai-so-do-i-d33f04d63534with) with r2ai

## Videos

- [Solving a crackme](https://infosec.exchange/@radareorg/111946255058894583)
- [De-obfuscation of malware Linux/Ladvix](https://asciinema.org/a/724126)
- [Analysis of the /fast option inside Linux/Trigona ransomware](https://asciinema.org/a/pBPEaJhp6cunWSKFpBUDTgPt4)
