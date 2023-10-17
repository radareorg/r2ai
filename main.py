#!/usr/bin/env python3

import os
import sys

try:
	r2aihome = os.path.dirname(os.readlink(__file__))
	sys.path.append(r2aihome)
except:
	pass

import time
import builtins
import traceback
import inquirer
import readline
import r2ai
import sys
from r2ai.utils import slurp

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

ais = {}
ai = r2ai.Interpreter()
ais[0] = ai

def r2_cmd(x):
	global ai
	res = x
	if have_rlang:
		oc = r2lang.cmd('e scr.color')
		r2lang.cmd('e scr.color=0')
		res = r2lang.cmd(x)
		r2lang.cmd('e scr.color=' + oc)
	elif r2 is not None:
		oc = r2.cmd('e scr.color')
		r2.cmd('e scr.color=0')
		res = r2.cmd(x)
		r2.cmd('e scr.color=' + oc)
	return res 

ai.local = True
# interpreter.model = "codellama-13b-instruct.Q4_K_M.gguf"
# ai.model = "TheBloke/CodeLlama-7B-Instruct-GGUF"
# interpreter.model = "TheBloke/codellama-34b-instruct.Q4_K_M.gguf"
ai.model = "TheBloke/CodeLlama-34B-Instruct-GGUF"
ai.model = "TheBloke/Wizard-Vicuna-7B-Uncensored-GPTQ"
# interpreter.model = "YokaiKoibito/falcon-40b-GGUF" ## fails
# interpreter.model = "ItelAi/Chatbot"
# pwd = os.getcwd()
ai.model = "models/models/codellama-7b-instruct.Q4_K_M.gguf"
ai.system_message = "" #

ai.model = "llama-2-7b-chat-codeCherryPop.ggmlv3.q4_K_M.gguf"
ai.model = "TheBloke/llama2-7b-chat-codeCherryPop-qLoRA-GGUF"
# interpreter.model = "/tmp/model.safetensors"
# interpreter.model = "TheBloke/CodeLlama-34B-Instruct-GGUF"
#interpreter.model = "models/models/codellama-34b-instruct.Q2_K.gguf"
#ai.model = "models/models/wizardlm-1.0-uncensored-llama2-13b.Q2_K.gguf"
# ai.model = "models/models/guanaco-7b-uncensored.Q2_K.gguf" 
#interpreter.model = "models/models/ggml-model-q4_0.gguf" # tinysmall -- very bad results

# ai.model = "models/models/mistral-7b-v0.1.Q4_K_M.gguf"
# ai.model = "models/models/mistral-7b-v0.1.Q4_K_M.gguf"
#interpreter.model = "models/models/mistral-7b-instruct-v0.1.Q2_K.gguf"
#interpreter.model = "TheBloke/Mistral-7B-Instruct-v0.1-GGUF"
#builtins.print("TheBloke/Mistral-7B-Instruct-v0.1-GGUF")

dir_path = os.path.dirname(os.path.realpath(__file__))
model_path = dir_path + "/" + ai.model
if os.path.exists(model_path):
	ai.model = model_path

help_message = """
Usage: r2ai [-option] ([query])
 r2ai !aa               run a r2 command
 r2ai -k                clear the screen
 r2ai -c [cmd] [query]  run the given r2 command with the given query
 r2ai -e [k[=v]]        set environment variable
 r2ai -h | ?            show this help
 r2ai -i [a.js] [query] load the contents of the given file into the query buffer
 r2ai -m [file/repo]    select model from huggingface repository or local file
 r2ai -n [num]          select the nth language model
 r2ai -q                quit/exit/^C
 r2ai -l                toggle the live mode
 r2ai -r [sysprompt]    define the role of the conversation
 r2ai -R                reset the chat conversation context
 r2ai -v                show r2ai version
"""

def runline(usertext):
	global ai
	usertext = usertext.strip()
	if usertext == "" or usertext.startswith("?") or usertext.startswith("-h"):
		builtins.print(help_message)
	elif usertext.startswith("clear") or usertext.startswith("-k"):
		builtins.print("\x1b[2J\x1b[0;0H\r")
	elif usertext.startswith("-m"):
		words = usertext.split(" ")
		if len(words) > 1:
			ai.model = words[1]
		else:
			builtins.print(ai.model)
	elif usertext == "reset" or usertext.startswith("-R"):
		ai.reset()
	elif usertext == "-q" or usertext == "exit":
		return "q"
	elif usertext.startswith("-e"):
		if len(usertext) == 2:
			print(ai.env)
		else:
			line = usertext[2:].strip().split("=")
			k = line[0]
			if len(line) > 1:
				v = line[1]
				if v == "":
					del ai.env[k]
				else:
					ai.env[k] = v
			else:
				try:
					print(ai.env[k])
				except:
					pass
	elif usertext.startswith("-s"):
		r2ai_repl()
	elif usertext.startswith("-r"):
		if len(usertext) > 2:
			ai.system_message = usertext[2:].strip()
		else:
			print(ai.system_message)
	elif usertext[0] == "$": # Deprecate
		if len(usertext) > 1:
			ai.system_message = usertext[1:]
		else:
			print(ai.system_message)
	elif usertext.startswith("-m"):
		ai.live_mode = not ai.live_mode
		lms = "enabled" if ai.live_mode else "disabled"
		print("live mode is " + lms)
	elif usertext.startswith("-l"):
		ai.live_mode = not ai.live_mode
		lms = "enabled" if ai.live_mode else "disabled"
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
#r2ai.chat("Q: " + que + ":\n["+tag+"]\n"+ res+"\n[/"+tag+"]\n")
		ai.chat("Human: " + que + ":\n["+tag+"]\n"+ res+"\n[/"+tag+"]\n")
	elif usertext.startswith("-n"):
		if usertext == "-n":
			for a in ais.keys():
				model = ais[a].model
				print(f"{a}  - {model}")
		else:
			index = int(usertext[2:])
			if index not in ais:
				ais[index] = r2ai.Interpreter()
				ais[index].model = ai.model
			ai = ais[index]
	elif usertext.startswith("-v"):
		print(r2ai.VERSION)
	elif usertext.startswith("-c"):
		words = usertext[2:].strip().split(" ", 1)
		res = r2_cmd(words[0])
		if len(words) > 1:
			que = words[1]
		else:
			que = input("[Query]>> ")
		tag = "CODE" # CODE, TEXT, ..
		ai.chat("Human: " + que + ":\n[" + tag + "]\n" + res + "\n[/" + tag + "]\n")
	elif usertext[0] == "!": # Deprecate. we have -c now
		if r2 is None:
			builtins.print("r2 is not available")
		elif usertext[1] == "!":
			res = r2_cmd(usertext[2:])
			que = input("[Query]>> ")
			ai.chat("Q: " + que + ":\n[INPUT]\n"+ res+"\n[/INPUT]\n") # , return_messages=True)
		else:
			builtins.print(r2_cmd(usertext[1:]))
	elif usertext.startswith("-"):
		builtins.print("Unknown flag. See 'r2ai -h' for help")
	else:
		ai.chat(usertext)
# r2ai.load(res)
# print(res)

def r2ai_repl():
	olivemode = ai.live_mode
	ai.live_mode = True
	prompt = "[r2ai:0x00000000]> "
	while True:
		if r2 is not None:
			off = r2_cmd("s").strip()
			if off == "":
				off = r2_cmd("s").strip()
			prompt = "[r2ai:" + off + "]>> "
		if ai.active_block is not None:
			#r2ai.active_block.update_from_message("")
			ai.end_active_block()
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
	ai.live_mode = olivemode

### MAIN ###
if len(sys.argv) > 1:
#	ai.live_mode = False
	for arg in sys.argv[1:]:
		runline(arg)
	sys.exit(0)
elif have_r2pipe:
	try:
		if "R2PIPE_IN" in os.environ.keys():
			r2 = r2pipe.open()
		else:
			file = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
			r2 = r2pipe.open(file)
	except:
		print("error")

if have_rlang:
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
else:
	r2ai_repl()
