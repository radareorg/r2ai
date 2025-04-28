# C-R2AI

This directory contains the C rewrite of the r2ai plugin for radare2.

## Installation

Requires radare2 from git if you want to use the stream HTTP APIs.

Otherwise the only requirement is a C compiler.

```console
make
make user-install
```

## Features

* Decompilation into any programming language
* Explain weaknesses and purpose of a function
* Function and local variable renaming, type propagation
* Ollama by default, any other remote AI service as choice
* Auto mode and function calling with any model
* Fix and improve function signatures
* Assistant mode with a REPL chat

## Experimental

* Own vector database for embeddings
* Custom reasoning engine with any model

## Usage

```console
[0x100003f58]> r2ai -h
Usage: r2ai   [-args] [...]
| r2ai -d                 Decompile current function
| r2ai -dr                Decompile current function (+ 1 level of recursivity)
| r2ai -a [query]         Resolve question using auto mode
| r2ai -e                 Same as '-e r2ai.'
| r2ai -h                 Show this help message
| r2ai -i [file] [query]  read file and ask the llm with the given query
| r2ai -m                 show selected model, list suggested ones, choose one
| r2ai -M                 show suggested models for each api
| r2ai -n                 suggest a better name for the current function
| r2ai -r                 enter the repl
| r2ai -R ([text])        refresh and query embeddings (see r2ai.data)
| r2ai -s                 function signature
| r2ai -x                 explain current function
| r2ai -v                 suggest better variables names and types
| r2ai -V[r]              find vulnerabilities in the decompiled code (-Vr uses -dr)
| r2ai [arg]              send a post request to talk to r2ai and print the output
[0x100003f58]> 
```

## Example

See [https://github.com/radareorg/r2ai-examples](https://github.com/radareorg/r2ai-examples)

```c
[0x100003f58]> r2ai -e api=claude
[0x100003f58]> r2ai -d
int main(int argc, char **argv, char **envp) {
    char buffer[32];
    int result = 0;
    if (argv[1] != NULL) {
        strcpy_chk(buffer, argv[1], 32);
    }
    return result;
}
[0x100003f58]> 
```

## TODO

* add "undo" command to drop the last message
* dump / restore conversational states (see -L command)
* Implement `~`, `|` and `>` and other r2shell features


## Messages API

The r2ai project includes a new API for managing messages and tool calls in conversations with AI models. This API is implemented in `messages.c` and `messages.h`.

### Key Functions

- `r2ai_messages_new()`: Create a new messages array
- `r2ai_messages_free(msgs)`: Free a messages array and all associated data
- `r2ai_messages_add(msgs, role, content, tool_call_id)`: Add a new message
- `r2ai_messages_add_tool_call(msgs, name, arguments, id)`: Add a tool call to the last message
- `r2ai_messages_last(msgs)`: Get the last message in the array
- `r2ai_messages_parse_json(msgs, json)`: Parse a JSON response into messages
- `r2ai_messages_clear(msgs)`: Clear all messages

### Example Usage

```c
// Create a new messages array
R2AI_Messages *msgs = r2ai_messages_new();

// Add a user message
r2ai_messages_add(msgs, "user", "What is the disassembly of function main?", NULL);

// Add an assistant message with a tool call
R2AI_Message *msg = r2ai_messages_add(msgs, "assistant", NULL, NULL);
r2ai_messages_add_tool_call(msgs, "r2cmd", "{\"command\":\"pdf@main\"}", "tool-123");

// Free all resources when done
r2ai_messages_free(msgs);
```
