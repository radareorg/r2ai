# r2ai-python

This directory contains the original implementation of the AI support for radare2 written in Python.

It is considered _deprecated_, but it's still useful and aims to be maintained, we recommend using decai or the C rewrite as alternatives.

The Python implementation consists in a module can be used in 3 different ways:

* commandline repl using r2pipe to spawn or connect to remote radare2 instances
* radare2 core plugin that is instantiated when placing it in the radare2 plugin's directory
* Python API to be used for writing your own scripts

## API Providers

The Python implementation focused on supporting the LlamaCpp Python module, which is somehow heavy to load in many environments, but it also supports litellm which provides access to many external connectors like ollama, openai, anthropic, gemini, etc.

## Deprecation Reasons

There are several reasons why this implementation is considered deprecated and not recommended to use:

1) It's Python.

 - Aka, it's slow, heavy loads in same process
 - Your system probably have multiple versions installed
 - The shell and radare2 python bindings are probably not the same
 - Required venv to be created (at least an extra 1GB)
 - Not typed, regressions and bugs appear at runtime

2) Goto 1

### Windows

On Windows you may follow the same instructions, just ensure you have the right python environment ready and create the venv to use

```cmd
git clone https://github.com/radareorg/r2ai
cd r2ai
set PATH=C:\Users\YOURUSERNAME\Local\Programs\Python\Python39\;%PATH%
python3 -m pip install .
python3 main.py
```

### Selecting the model

- List all downloaded models: `-m`
- Get a short list of models: `-MM`
- Help: `-h`

**Example selecting a remote models:**

```
[r2ai:0x00006aa0]> -m anthropic:claude-3-7-sonnet-20250219
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

**Example selecting a local model served by Ollama**

Download a model and make it available through Ollama:

```
$ ollama ls
NAME                  ID              SIZE      MODIFIED     
codegeex4:latest      867b8e81d038    5.5 GB    23 hours ago  
```

Use it from r2ai by prefixing its name with `ollama/`

```
[r2ai:0x00002d30]> -m ollama/codegeex4:latest
[r2ai:0x00002d30]> hi
Hello! How can I assist you today?
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

### r2ai Configuration settings

List all settings with `-e`

| Key         | Explanation                           |
| ----------- | ------------------------------------- |
| debug_level | All verbose messages for level 1. Default is 2 |
| auto.max_runs | Maximum number of questions the AI is allowed to ask r2 in auto mode. |
| auto.hide_tool_output | By default false, consequently output of r2cmd, run_python etc is shown. Set to `true` to hide those internal messages. |
| chat.show_cost | Show the cost of each request to the AI if true |

