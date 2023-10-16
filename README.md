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

## Download the default model

* [https://mega.nz/file/kocgEbRC#3lBMydGuZ6GWvNG0xfdJNa5s9P2M-iDBlP32HnHSw_A](https://mega.nz/file/kocgEbRC#3lBMydGuZ6GWvNG0xfdJNa5s9P2M-iDBlP32HnHSw_A)

But you can use any other language model from HuggingFace.

## Installation

Just run `make` .. or well `python main.py /path/to/file`

You can also install it via `r2pm -i r2ai`

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
