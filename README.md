```
,______  .______ .______  ,___
: __   \ \____  |:      \ : __|
|  \____|/  ____||  _,_  || : |
|   :  \ \   .  ||   :   ||   |
|   |___\ \__:__||___|   ||   |
|___|        :       |___||___|
             *
```

Run r2ai in local, without internet or leaking any data. Use your CPU/GPU/NPU and interact with r2 using natural language. The current implementation is based on llama and the default model is `CodeLlama-CherryPop`

--pancake

## Features

* Prompt the language model without internet requirements
* Slurp file contents and make actions on that
* Embed the output of an r2 command and ask the LLM to resolve questions
* Define different system-level assistant role
* Set environment variables to provide context to the language model
* Live with repl and batch mode from cli or r2 prompt
* Accessible as an r2lang-python plugin, keeps session state inside radare2
* Scriptable from bash, r2pipe, and javascript (r2papi)
* Use different models, dynamically adjust query template
  * Load multiple models and make them talk between them

## Installation

The easiest way to run and install r2ai is by installing the latest r2 from git and run these lines:

```bash
r2pm -i rlang-python # optional
pip3 install rich inquirer llama-cpp tokentrim hugging_face appdirs
r2pm -ci r2ai
```

On recent Debian/Ubuntu systems the `pip` tool is no longer working, because it conflicts with the system packages. The best way to do this is with `venv`:

```bash
python -m venv r2ai
. r2ai/bin/activate
pip install rich inquirer llama-cpp-python tokentrim hugging_face appdirs
r2pm -r r2ai
```

On native Windows follow these instructions (no need to install radare2 or use r2pm), note that you need Python 3.8 or higher:

```cmd
git clone https://github.com/radareorg/r2ai
cd r2ai
set PATH=C:\Users\YOURUSERNAME\Local\Programs\Python\Python39\;%PATH%
python -m pip install rich inquirer llama-cpp-python tokentrim hugging_face appdirs pyreadline3
python main.py
```

## Usage

There are 4 different ways to run `r2ai`:

* Standalone and interactive: `r2pm -r r2ai`
* Batch mode: `r2ai '-r act as a calculator' '3+3=?'`
* From radare2 (requires `r2pm -ci rlang-python`): `r2 -c 'r2ai -h'`
* Using r2pipe: `#!pipe python main.py`

## Examples

You can interact with r2ai from standalone python, from r2pipe via r2 keeping a global state or using the javascript intrepreter embedded inside `radare2`.

* [conversation.r2.js](examples/conversation.r2.js) - load two models and make them talk to each other

### Development/Testing

Just run `make` .. or well `python main.py /path/to/file`

It's also possible to install it with `conda`, which is the recommended way on Macs.

* https://developer.apple.com/metal/pytorch/

```sh
curl -O https://repo.anaconda.com/miniconda/Miniconda3-latest-MacOSX-arm64.sh
sh Miniconda3-latest-MacOSX-arm64.sh
```

```sh
conda install pytorch torchvision torchaudio -c pytorch-nightly
conda run pip install inquirer rich appdirs huggingface_hub tokentrim llama-cpp-python
```

### TODO

* add "undo" command to drop the last message
* dump / restore conversational states
* custom prompt templates

### Kudos

The original code of r2ai is based on OpenInterpreter. I want to thanks all the contributors to this project as they made it possible to build r2ai taking their code as source for this.  Kudos to Killian and all the contributors.
