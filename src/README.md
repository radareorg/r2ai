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
| r2ai -d [query]         Ask a question on the current function
| r2ai -dr                Decompile current function (+ 1 level of recursivity)
| r2ai -a [query]         Resolve question using auto mode
| r2ai -e                 Same as '-e r2ai.'
| r2ai -h                 Show this help message
| r2ai -i [file] [query]  read file and ask the llm with the given query
| r2ai -m                 show selected model, list suggested ones, choose one
| r2ai -n                 suggest a better name for the current function
| r2ai -r                 enter the chat repl
| r2ai -L                 show chat logs (See -Lj for json). Only for auto mode.
| r2ai -L-[N]             delete the last (or N last messages from the chat history)
| r2ai -R                 reset the chat conversation context
| r2ai -Rq ([text])       refresh and query embeddings (see r2ai.data)
| r2ai -s                 function signature
| r2ai -x                 explain current function
| r2ai -v                 suggest better variables names and types
| r2ai -V[r]              find vulnerabilities in the decompiled code (-Vr uses -dr)
| r2ai [arg]              send a post request to talk to r2ai and print the output
[0x100003f58]> 
```

## Configuration

These can be set with `r2ai -e <keyname>=<value>`

| Setting name     | Description                                                                                    |
|------------------|------------------------------------------------------------------------------------------------|
| r2ai.api         | Name of the provider e.g `openai`. List possibilities with `r2ai -e r2ai.api=?`                |
| r2ai.model       | Model name. List possibilities with `r2ai -e r2ai.model=?`                                     |
| r2ai.baseurl     | Remote LLM HTTP server e.g http://127.0.0.1:11434. |
| r2ai.max_tokens  | Maximum output tokens or maximum total tokens. Check the appropriate limits for your model     |
| r2ai.temperature | How creative the model should be. 0=not creative, 1=very creative                              |
| r2ai.cmds        | R2 command to issue and send output in context to model                                        |
| r2ai.lang        | Tells LLM which programming language to use for decompilation result. Only works for `r2ai -d` |
| r2ai.hlang       | Tells LLM in which language to speak                                                           |
| r2ai.prompt      | User prompt to send to LLM with `r2ai -d` |
| r2ai.auto.max_runs | Maximum loops when using auto mode `r2ai -a` |
| r2ai.auto.hide_tool_output | Only for auto mode `r2ai -a`. Will not show the output of the tool which ran locally |
| r2ai.auto.yolo | Set this to true if you don't want r2ai to ask you for approval before running commands sent by the LLM. This is **dangerous**. Recommendation: **leave this to false** unless you fully trust your LLM not to create havoc! |
| r2ai.http.use_files | If you get CURL argument too long error, set this to true and arguments will be stored in a file.|



## Example

- Get the [substitute example binary](https://github.com/radareorg/r2ai/tree/master/examples)
- Initialize r2 and r2ai
```
$ r2 ./substitute
[0x000010a0]> r2ai -e api=anthropic
[0x000010a0]> r2ai -e model=claude-3-7-sonnet-20250219
[0x000010a0]> aa
```

- Decompile the main function: `r2ai -d`

```
[0x000010a0]> s main
[0x00001303]> r2ai -d
int main(int argc, char **argv, char **envp) {
    char input[256];
    char encrypted[512];
    char *alphabet = "QWERTYUIOPASDFGHJKLZXCVBNM";
    
    printf("Enter text to encrypt: ");
    fgets(input, 256, stdin);
    
    input[strcspn(input, "\n")] = 0;
    
    substitute(input, alphabet, encrypted, 0);
    printf("Encrypted text: %s\n", encrypted);
    
    substitute(encrypted, alphabet, input, 1);
    printf("Decrypted text: %s\n", input);
    
    return 0;
}
```

- Ask a question on the current function: `r2ai -d query`

```
[0x00001303]> r2ai -d what is input buffer size?
Based on the disassembly provided, I can see that the input buffer size is 0x100 (256) bytes.

This is visible in the call to `fgets()` where we see:
```
esi = 0x100
rdi = rax  // pointing to var_110h which is the input buffer
sym.imp.fgets()  // char *fgets("", 0x00000100, 0)
```

The fgets function is being called with a second argument of 0x100, which specifies the maximum number of characters to read (including the null terminator). This means the program allocates a 256-byte buffer for user input.
```

Note that the context is **reset between each direct query**. For example, the context of the second command `r2ai -d what is input buffer size?` does not contain the request/response of the first `r2ai -d`.

- Find vulnerabilities: `r2ai -V`

```
[0x00001303]> r2ai -V
# Vulnerability Analysis

## Identified Vulnerabilities

1. **Buffer Overflow Risk**: The program uses `fgets()` with a 256-byte buffer to read user input, but doesn't validate if the substitute function's target buffer can handle this much data.

2. **Lack of Input Validation**: There appears to be no validation of the input character range, which could lead to unexpected behavior if special characters are used.

3. **Predictable Encryption**: The cipher uses a hardcoded key "QWERTYUIOPASDFGHJKLZXCVBNM", making it trivially breakable.

4. **Insufficient Memory Handling**: No verification that memory allocations succeed before use.

## Sample Exploit

```python
# Buffer overflow exploit example
from pwn import *

# Connect to the target (adjust as needed)
p = process('./cipher_program')

# Create payload: 256 'A's + return address override
payload = b"A" * 256 + p64(0x4141414141414141)  # Example address

# Send the payload
p.sendlineafter(b"Enter text to encrypt: ", payload)
p.interactive()
```

## Security Recommendations

1. **Implement Buffer Size Checks**: Ensure that destination buffers are large enough for the operation and implement bounds checking.

2. **Input Validation**: Validate all user inputs for expected character ranges and length.

3. **Dynamic Key Generation**: Use cryptographically secure random number generators to create unique keys for each session.

4. **Memory Safety**: Use secure memory allocation practices with proper error handling.

5. **Modern Cryptography**: Replace the simple substitution cipher with standard cryptographic libraries (e.g., OpenSSL).

6. **Stack Protection**: Compile with stack canaries (`-fstack-protector-all`) and address space layout randomization (ASLR).

7. **Error Handling**: Implement proper error checking and graceful failure mechanisms.

8. **Secure Coding Practices**: Follow guidelines like OWASP for secure coding standards.
```


- Automatic mode: `r2ai -a query`. In the auto mode, r2ai offers use of tools.

```
[0x00001303]> r2ai -a The main implements a substitution algorithm. Give me an input that would end up as RADARE2 when substituted
[r2cmd]> 
[0x00001303]> afl~main
afl~main

0x00001303    1    231 main

[Assistant]

I'll analyze the substitution algorithm in the main function to determine what input would result in "RADARE2" after substitution. Let me examine the main function code.
[r2cmd]> 
[0x00001303]> pdf @ main
...
```

- See the chat logs (only in auto mode): `r2ai -L`:

```
[r2ai] Chat Logs (12 messages)
Note: System prompt is applied automatically but not stored in history

[user]: The main implements a substitution algorithm. Give me an input that would end up as RADARE2 when substituted

[assistant]: I'll analyze the substitution algorithm in the main function to determine what input would result in "RADARE2" after substitution. Let me examine the main function code.
  [tool call]: r2cmd
    {"command":"pdf @ main"}
```



## TODO

* add "undo" command to drop the last message
* dump / restore conversational states (see -L command)
* Implement `~`, `|` and `>` and other r2shell features
* keep context between direct commands unless explicitly reset
* modify context if tool command is user edited


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
