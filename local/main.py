#!/usr/bin/env python3

import os
import sys

r2aihome = os.path.dirname(os.readlink(__file__))
sys.path.append(r2aihome)

import time
import builtins
# from rich import print
import traceback
import inquirer
import readline
import r2ai

r2 = None
have_rlang = False
have_r2pipe = False
try:
	import r2lang
	have_rlang = True
except:
	try:
		import r2pipe
		have_r2pipe = True
	except:
		pass
def r2_cmd(x):
	if have_rlang:
		return r2lang.cmd(x)
	if r2 is not None:
		return r2.cmd(x)
	return x

r2ai.local = True
# interpreter.model = "codellama-13b-instruct.Q4_K_M.gguf"
# interpreter.model = "TheBloke/CodeLlama-7B-Instruct-GGUF"
# interpreter.model = "TheBloke/codellama-34b-instruct.Q4_K_M.gguf"
r2ai.model = "TheBloke/CodeLlama-34B-Instruct-GGUF"
r2ai.model = "TheBloke/Wizard-Vicuna-7B-Uncensored-GPTQ"
# interpreter.model = "YokaiKoibito/falcon-40b-GGUF" ## fails
# interpreter.model = "ItelAi/Chatbot"
# pwd = os.getcwd()
# interpreter.model = pwd + "codellama-13b-python.ggmlv3.Q4_1.gguf"
r2ai.system_message = "" #

r2ai.model = "llama-2-7b-chat-codeCherryPop.ggmlv3.q4_K_M.gguf"
# interpreter.model = "/tmp/model.safetensors"
# interpreter.model = "TheBloke/CodeLlama-34B-Instruct-GGUF"
#interpreter.model = "models/models/codellama-34b-instruct.Q2_K.gguf"
# interpreter.model = "models/models/wizardlm-1.0-uncensored-llama2-13b.Q2_K.gguf"
# interpreter.model = "models/models/guanaco-7b-uncensored.Q2_K.gguf" 
#interpreter.model = "models/models/ggml-model-q4_0.gguf" # tinysmall -- very bad results

#interpreter.model = "models/models/mistral-7b-v0.1.Q4_K_M.gguf"
#interpreter.model = "models/models/mistral-7b-instruct-v0.1.Q2_K.gguf"
#interpreter.model = "TheBloke/Mistral-7B-Instruct-v0.1-GGUF"
# builtins.print("TheBloke/Mistral-7B-Instruct-v0.1-GGUF")

dir_path = os.path.dirname(os.path.realpath(__file__))
model_path = dir_path + "/" + r2ai.model
if os.path.exists(model_path):
	r2ai.model = model_path

def slurp(f):
	fd = open(f)
	res = fd.read()
	fd.close()
	return "" + res

if have_r2pipe:
	try:
		if "R2PIPE_IN" in os.environ.keys():
			r2 = r2pipe.open()
		else:
			file = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
			r2 = r2pipe.open(file)
	except:
		print("error")

help_message = """
Usage: r2ai [-option] ([query])
 r2ai !aa               analyze the binary, run this r2 command without modifying the query buffer
 r2ai -k                clear the screen
 r2ai -c [cmd] [query]  run the given r2 command with the given query
 r2ai -e [k[=v]]        set environment variable
 r2ai -h | ?            show this help
 r2ai -i [a.js] [query] load the contents of the given file into the query buffer
 r2ai -m [file/repo]    select model from huggingface repository or local file
 r2ai -q                quit/exit/^C
 r2ai -l                toggle the live mode
 r2ai -r [sysprompt]    define the role of the conversation
 r2ai -R                reset the chat conversation context
 r2ai -v                show r2ai version
"""

def runline(usertext):
	usertext = usertext.strip()
	if usertext == "" or usertext.startswith("?") or usertext.startswith("-h"):
		builtins.print(help_message)
	elif usertext.startswith("clear") or usertext.startswith("-k"):
		builtins.print("\x1b[2J\x1b[0;0H\r")
	elif usertext.startswith("-m"):
		words = usertext.split(" ")
		if len(words) > 1:
			r2ai.model = words[1]
		else:
			builtins.print(r2ai.model)
	elif usertext == "reset" or usertext.startswith("-R"):
		r2ai.reset()
	elif usertext == "-q" or usertext == "exit":
		return "q"
	elif usertext.startswith("-e"):
		if len(usertext) == 2:
			print(r2ai.env)
		else:
			line = usertext[2:].strip().split("=")
			k = line[0]
			if len(line) > 1:
				v = line[1]
				if v == "":
					del r2ai.env[k]
				else:
					r2ai.env[k] = v
			else:
				try:
					print(r2ai.env[k])
				except:
					pass
	elif usertext.startswith("-s"):
		r2ai_repl()
	elif usertext.startswith("-r"):
		if len(usertext) > 2:
			r2ai.system_message = usertext[2:].strip()
		else:
			print(r2ai.system_message)
	elif usertext[0] == "$": # Deprecate
		if len(usertext) > 1:
			r2ai.system_message = usertext[1:]
		else:
			print(r2ai.system_message)
	elif usertext.startswith("-l"):
		r2ai.live_mode = not r2ai.live_mode
		lms = "enabled" if r2ai.live_mode else "disabled"
		print("live mode is " + lms)
	elif usertext.startswith("-i"):
		text = usertext[2:].strip()
		words = text.split(" ", 1)
		res = slurp(words[0])
		if len(words) > 1:
			que = words[1]
		else:
			que = input("[Query]>> ")
		tag = "CODE" # INPUT , TEXT, ..
		r2ai.chat("Q: " + que + ":\n["+tag+"]\n"+ res+"\n[/"+tag+"]\n")
	elif usertext.startswith("-v"):
		print(r2ai.VERSION)
	elif usertext.startswith("-c"):
		words = usertext[2:].strip().split(" ", 1)
		res = r2_cmd(words[0])
		if len(words) > 1:
			que = words[1]
		else:
			que = input("[Query]>> ")
		tag = "INPUT" # CODE, TEXT, ..
		r2ai.chat("Q: " + que + ":\n[" + tag + "]\n" + res + "\n[/" + tag + "]\n")
	elif usertext[0] == "!": # Deprecate. we have -c now
		if r2 is None:
			builtins.print("r2 is not available")
		elif usertext[1] == "!":
			res = r2_cmd(usertext[2:])
			que = input("[Query]>> ")
			r2ai.chat("Q: " + que + ":\n[INPUT]\n"+ res+"\n[/INPUT]\n") # , return_messages=True)
		else:
			builtins.print(r2_cmd(usertext[1:]))
	elif usertext.startswith("-"):
		builtins.print("Unknown flag. See 'r2ai -h' for help")
	else:
		r2ai.chat(usertext)
# r2ai.load(res)
# print(res)

def r2ai_repl():
	olivemode = r2ai.live_mode
	r2ai.live_mode = True
	prompt = "[r2ai:0x00000000]> "
	while True:
		if r2 is not None:
			off = r2_cmd("s").strip()
			if off == "":
				off = r2_cmd("s").strip()
			prompt = "[r2ai:" + off + "]>> "
		if r2ai.active_block is not None:
			#r2ai.active_block.update_from_message("")
			r2ai.end_active_block()
		try:
			usertext = input(prompt).strip()
		except:
			break
		try:
			if runline(usertext) == "q":
				print("leaving")
				break
		except:
			traceback.print_exc()
			continue
	r2ai.live_mode = olivemode

### MAIN ###
try:
	import r2lang

	def r2ai_rlang_plugin(a):
		def _call(s):
			if s.startswith("r2ai"):
				usertext = s[4:].strip()
				try:
					runline(usertext)
				except Exception as e:
					print(e)
					traceback.print_exc()
				return True;
			return False

		return {
			"name": "r2ai",
			"license": "MIT",
			"desc": "run llama language models in local inside r2",
			"call": _call,
		}

	r2lang.plugin("core", r2ai_rlang_plugin)
except:
	r2ai_repl()
