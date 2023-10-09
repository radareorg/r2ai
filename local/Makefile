MODEL=llama-2-7b-chat-codeCherryPop.ggmlv3.q4_K_M.gguf
R2_USER_PLUGINS=$(shell r2 -H R2_USER_PLUGINS)
PWD=$(shell pwd)

all: $(MODEL)

run:
	python3 main.py

$(MODEL): deps
	git clone https://github.com/radareorg/r2ai-models
	make -C r2ai-models
	ln -fs $(PWD)/r2ai-models/$(MODEL) $(PWD)/$(MODEL)

deps:
	pip3 install rich inquirer python-dotenv openai litellm tokentrim

install user-install:
	ln -fs $(PWD)/main.py $(R2_USER_PLUGINS)/r2ai.py

uninstall user-uninstall:
	rm -f $(R2_USER_PLUGINS)/r2ai.py
