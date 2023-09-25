MODEL=llama-2-7b-chat-codeCherryPop.ggmlv3.q4_K_M.gguf
PWD=$(shell pwd)

all: $(MODEL)

run:
	python main.py

$(MODEL): deps
	git clone https://github.com/radareorg/r2ai-models
	make -C r2ai-models
	ln -fs $(PWD)/r2ai-models/$(MODEL) $(PWD)/$(MODEL)

deps:
	pip install rich inquirer python-dotenv openai litellm tokentrim
