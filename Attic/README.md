# OpenAI GPT3 plugin for radare2

This plugin allows you to describe functions in radare2 using
the openai public API.

## Compilation

The plugin is written in Typescript, but don't worry, you just need
to type `make` to get everything compiled into a single `r2ai.js`.

## Usage

First of all you must login in `https://www.openai.com` and create
a new api key to use it.

Open a terminal and set the `OPENAI_API_KEY` env var with your key.

```sh
export OPENAI_API_KEY="sk-uaVxaKNMvobxyRkramoIjtT3BlbkFJjEOjcT1gj3cG9C2CcQ5"
```

## Installation

Right now that's just a PoC, so there's no installation but you can define
an alias to run the script from the r2 shell.

```sh
$ r2 -c '$ai=. r2ai.js' /bin/ls
```

## Clippy!

Reading text is boring, but you can always take advantage of the text-to-speech
functionality of radare2 to listen to the description while reading the assembly

```
> %R2AI_TTS=1
> $ai
 ╭──╮    ╭───────────────────────────────────────────────────╮
 │ ╶│╶   │                                                   │
 │ O o  <  The decompiled function prints out "Hello World". │
 │  │  ╱ │                                                   │
 │ ╭┘ ╱  ╰───────────────────────────────────────────────────╯
 │ ╰ ╱
 ╰──'
```

## Future

There are many more applications that we can take advantage in radare2

* Make questions about how to do something with r2pipe
* Ask what's an r2 command doing
* Pass the assembly code directly
* Support more languages (openai knows the language of the question and answers in the same language)
* Find checksums
* Identify crypto algorithms

## Looking for contributions

This is opensource, which means that anyone can contribute and play with it.

So feel free to have fun and submit a PR if you think so!

--pancake
