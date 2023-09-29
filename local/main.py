#!/usr/bin/env python3

import time
import sys
import builtins
from rich import print
import inquirer
import readline
import interpreter
import os

interpreter.local = True
# interpreter.model = "codellama-13b-instruct.Q4_K_M.gguf"
# interpreter.model = "TheBloke/CodeLlama-7B-Instruct-GGUF"
# interpreter.model = "TheBloke/codellama-34b-instruct.Q4_K_M.gguf"
interpreter.model = "TheBloke/CodeLlama-34B-Instruct-GGUF"
interpreter.model = "TheBloke/Wizard-Vicuna-7B-Uncensored-GPTQ"
# interpreter.model = "YokaiKoibito/falcon-40b-GGUF" ## fails
# interpreter.model = "ItelAi/Chatbot"
# pwd = os.getcwd()
# interpreter.model = pwd + "codellama-13b-python.ggmlv3.Q4_1.gguf"
interpreter.system_message = "" #

interpreter.model = "llama-2-7b-chat-codeCherryPop.ggmlv3.q4_K_M.gguf"
# interpreter.model = "/tmp/model.safetensors"
# interpreter.model = "TheBloke/CodeLlama-34B-Instruct-GGUF"
#interpreter.model = "models/models/codellama-34b-instruct.Q2_K.gguf"
#interpreter.model = "models/models/wizardlm-1.0-uncensored-llama2-13b.Q2_K.gguf"
#interpreter.model = "models/models/guanaco-7b-uncensored.Q2_K.gguf" 
#interpreter.model = "models/models/ggml-model-q4_0.gguf" # tinysmall -- very bad results

dir_path = os.path.dirname(os.path.realpath(__file__))
interpreter.model = dir_path + "/" + interpreter.model

def slurp(f):
	fd = open(f)
	res = fd.read()
	fd.close()
	return "" + res

# script = slurp("/tmp/util.c")
# usertext = "Describe the purpose of this C function in a single sentence and add it as a comment on top: [CODE]" + script + "[/CODE]"
# usertext = "Add comments in the following code to make it easier to understand: [CODE]" + script + "[/CODE]"
# usertext = "Tell me what's the use case for this function and when it should not be used: [CODE]" + script + "[/CODE]"
# usertext = "Digues en Català i en una sola frase si aquesta funció modifica els continguts dels arguments que reb: [CODE]" + script + "[/CODE]"
# usertext = "Tell me what's not obvious or wrong in this function: [CODE]" + script + "[/CODE]"
# usertext = "How to bind this function from Python? [CODE]" + script + "[/CODE]"
# interpreter.chat(usertext)
# exit()

r2 = None
try:
	import r2pipe
	if "R2PIPE_IN" in os.environ.keys():
		r2 = r2pipe.open()
	else:
		file = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
		r2 = r2pipe.open(file)
except:
	print("error")

#parameter_choices = ["jeje"]
# readline.add_history(user_input)
#questions = [inquirer.List('param', message="Parameter count (smaller is faster, larger is more capable)", choices=parameter_choices)]
#inquirer.prompt(questions)

help_message = """
Usage: [!r2command] | [chat-query] | [command]
Examples:
  ?      -> show this help
  !!aod  -> run the 'aod' command in r2 to describe the instruction and append it to the query
  !aa    -> analyze the binary, run this r2 command without modifying the query buffer
  :a.js  -> load the contents of the given file into the query buffer
  %k=v   -> set environment variable
  $system prompt -> define the role of the conversation
  which instruction corresponds to this description? -> the query for the chat model
  reset  -> reset the chat (same as pressing enter with an empty line)
  clear  -> clear the screen
  q      -> quit/exit/^C
"""

def runline(usertext):
	if len(usertext) < 1:
		builtins.print() # do nothing
	elif usertext[0] == "?":
		builtins.print(help_message)
	elif usertext == "clear":
		builtins.print("\x1b[2J\x1b[0;0H\r")
	elif usertext == "reset":
		builtins.print("Forgot")
		interpreter.reset()
	elif usertext[0] == "q" or usertext == "exit":
		return "q"
	elif usertext[0] == "%":
		if len(usertext) == 1:
			print(interpreter.env)
		else:
			line = usertext[1:].split("=")
			k = line[0]
			if len(line) > 1:
				v = line[1]
				interpreter.env[k] = v
			else:
				try:
					print(interpreter.env[k])
				except:
					pass
	elif usertext[0] == "$":
		if len(usertext) > 1:
			interpreter.system_message = usertext[1:]
		else:
			print(interpreter.system_message)
	elif usertext[0] == ":":
		res = slurp(usertext[1:])
		que = input("[Query]>> ")
		# interpreter.chat("Q: " + que + ":\n[INPUT]\n"+ res+"\n[/INPUT]\n") # , return_messages=True)
		interpreter.chat("Q: " + que + ":\n[CODE]\n"+ res+"\n[/CODE]\n")
	elif usertext[0] == "!":
		if r2 is None:
			builtins.print("r2 is not available")
		elif usertext[1] == "!":
			res = r2.cmd(usertext[2:])
			que = input("[Query]>> ")
			interpreter.chat("Q: " + que + ":\n[INPUT]\n"+ res+"\n[/INPUT]\n") # , return_messages=True)
		else:
			builtins.print(r2.cmd(usertext[1:]))
	else:
		interpreter.chat(usertext)
# interpreter.load(res)
# print(res)

prompt = "[r2ai:0x00000000]> "
while True:
	if r2 is not None:
		off = r2.cmd("s").strip()
		if off == "":
			off = r2.cmd("s").strip()
		prompt = "[r2ai:" + off + "]>> "
	if interpreter.active_block is not None:
		#interpreter.active_block.update_from_message("")
		interpreter.active_block.end()
	try:
		usertext = input(prompt).strip()
	except:
		break
	try:
		if runline(usertext) == "q":
			break
	except:
		continue
