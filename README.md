```
,______  .______ .______  ,___
: __   \ \____  |:      \ : __|
|  \____|/  ____||  _,_  || : |
|   :  \ \   .  ||   :   ||   |
|   |___\ \__:__||___|   ||   |
|___|        :       |___||___|
             *       --pancake
```

Run a language model in local, without internet, to entertain you or help answering questions about radare2 or reverse engineering in general. Note that models used by r2ai are pulled from external sources which may behave different or respond unrealible information. That's why there's an ongoing effort into improving the post-finetuning using memgpt-like techniques which can't get better without your help!

<p align="center">
  <img src="doc/r2clippy.jpg">
</p>

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

This is optional ans system dependant. but on recent Debian/Ubuntu systems the `pip` tool is no longer working, because it conflicts with the system packages. The best way to do this is with `venv`:

```bash
python -m venv r2ai
. r2ai/bin/activate
```

```bash
pip install -r requirements.txt
r2pm -r r2ai
```

Additionally you can get the `r2ai` command inside r2 to run as an rlang plugin by installing the bindings:

```bash
r2pm -i rlang-python
make user-install
```

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
