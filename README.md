```
.______  .______ .______  .___ 
: __   \ \____  |:      \ : __|
|  \____|/  ____||   .   || : |
|   :  \ \      ||   :   ||   |
|   |___\ \__:__||___|   ||   |
|___|        :       |___||___|
             •                 
```

Run r2ai in local, no google bard or chatgpt. Just use your CPU/GPU/NPU and interact with r2 using natural language.

--pancake

## Installation

```
pip3 install rich inquirer python-dotenv openai litellm tokentrim
r2pm -i r2ai
```

## Development/Testing

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

## Features

* Prompt the language model without internet requirements
* Slurp file contents and make actions on that
* Embed the output of an r2 command and ask the LM to resolve questions
* Define different system-level assistant role
* Set environment variables to provide context to the language model
* Live with repl and batch mode from cli or r2 prompt
* Accessible as an r2lang-python plugin, keeps session state inside radare2
* Scriptable from bash, r2pipe, and javascript (r2papi)
* Use different models, dynamically adjust query template
  * Load multiple models and make them talk between them

## TODO

* add "undo" command
