#!/usr/bin/env python3

import os
import sys

try:
	r2aihome = os.path.dirname(os.readlink(__file__))
	sys.path.append(r2aihome)
except:
	pass

import traceback
import r2ai
from r2ai.utils import slurp
from r2ai.models import set_default_model
from r2ai import bubble
from r2ai.const import R2AI_HISTFILE, R2AI_HOMEDIR, R2AI_RCFILE
from r2ai.voice import stt

OPENAI_KEY = ""
try:
	if "HOME" in os.environ:
		os.environ["OPENAI_KEY"] = slurp(os.environ["HOME"] + "/.r2ai.openai-key").strip()
		print("[R2AI] Loading OpenAI key from ~/.r2ai.openai-key")
except:
	pass

have_readline = False

try:
    import readline
    readline.read_history_file(R2AI_HISTFILE)
    have_readline = True
except:
    pass #readline not available

r2 = None
have_rlang = False
have_r2pipe = False
within_r2 = False
print = print
if os.name != "nt":
	try:
		import r2lang
		have_rlang = True
		print = r2lang.print
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
		oc = r2lang.cmd('e scr.color').strip()
		r2lang.cmd('e scr.color=0')
		res = r2lang.cmd(x)
		r2lang.cmd('e scr.color=' + oc)
	elif r2 is not None:
		oc = r2.cmd('e scr.color').strip()
		r2.cmd('e scr.color=0')
		res = r2.cmd(x)
		r2.cmd('e scr.color=' + oc)
	return res

help_message = """Usage: r2ai [-option] ([query])
 r2ai !aa               run a r2 command
 r2ai -a                query with audio voice
 r2ai -A                enter the voice chat loop
 r2ai -k                clear the screen
 r2ai -c [cmd] [query]  run the given r2 command with the given query
 r2ai -e [k[=v]]        set environment variable
 r2ai -f [file]         load file and paste the output
 r2ai -h                show this help
 r2ai . [file]          interpret r2ai script with access to globals
 r2ai -i [file] [query] load the file contents and prompt it with the given query
 r2ai -m [file/repo]    select model from huggingface repository or local file
 r2ai -M                list supported and most common models from hf
 r2ai -n [num]          select the nth language model
 r2ai -q                quit/exit/^C
 r2ai -L                show chat logs
 r2ai -r [sysprompt]    define the role of the conversation
 r2ai -r2               enter the r2clippy assistant mode
 r2ai -rf [doc/role/.f] load contents of a file to define the role
 r2ai -R                reset the chat conversation context
 r2ai -t [temp]         from 0.0001 to 10 your scale to randomness in my replies
 r2ai -v                show r2ai version
 r2ai -w                toggle including LLM responses into the query (False is faster)"""


def runline(usertext):
	global print
	global ai
	usertext = usertext.strip()
	if usertext == "" or usertext.startswith("#"):
		return
	if usertext.startswith("?") or usertext.startswith("-h"):
		print(help_message)
	elif usertext.startswith("clear") or usertext.startswith("-k"):
		print("\x1b[2J\x1b[0;0H\r")
	elif usertext.startswith("-M"):
		r2ai.models()
	elif usertext.startswith("-m"):
		words = usertext.split(" ")
		if len(words) > 1:
			ai.model = words[1]
			ai.env["llm.model"] = ai.model
			set_default_model(ai.model)
		else:
			print(ai.model)
	elif usertext == "reset" or usertext.startswith("-R"):
		ai.reset()
	elif usertext.startswith("-t"):
		if usertext == "-t":
			print(ai.temperature)
		else:
			ai.temperature = float (usertext[2:])
			ai.env["llm.temperature"] = str(ai.temperature)
	elif usertext == "-A":
		ai.env["chat.voice"] = "true"
		old_live = ai.env["chat.live"]
		ai.env["chat.live"] = "false"
		while True:
			usertext = stt(4, ai.env["voice.lang"])
			if usertext != "":
				print(f"User: {usertext}")
				ai.chat(usertext)
		ai.env["chat.live"] = old_live
		ai.env["chat.voice"] = "false"
	elif usertext == "-a":
		ai.env["chat.voice"] = "true"
		old_live = ai.env["chat.live"]
		ai.env["chat.live"] = "true"
		usertext = stt(4, ai.env["voice.lang"])
		print(usertext)
		ai.chat(usertext)
		ai.env["chat.live"] = old_live
		ai.env["chat.voice"] = "false"
	elif usertext == "-q" or usertext == "exit":
		return "q"
	elif usertext == "-r2":
		ai.env["data.use"] = "true"
		ai.env["data.hist"] = "true"
		ai.env["data.path"] = f"{R2AI_HOMEDIR}/doc/"
		ai.env["chat.bubble"] = "true"
		runline(f"-rf {R2AI_HOMEDIR}/doc/role/r2clippy.txt")
	elif usertext.startswith("-e"):
		if len(usertext) == 2:
			for k in ai.env.keys():
				v = ai.env[k]
				print(f"-e {k}={v}")
		else:
			line = usertext[2:].strip().split("=")
			k = line[0]
			if len(line) > 1:
				v = line[1]
				if v == "":
#					del ai.env[k]
					ai.env[k] = ""
				elif k in ai.env:
					ai.env[k] = v
				else:
					print("Invalid config key")
			else:
				try:
					print(ai.env[k])
				except:
					print("Invalid config key")
					pass
	elif usertext.startswith("-w"):
		ai.withresponse = not ai.withresponse
		print(ai.withresponse)
	elif usertext.startswith("-s"):
		r2ai_repl()
	elif usertext.startswith("-rf"):
		if len(usertext) > 2:
			fname = usertext[3:].strip()
			try:
				ai.system_message = slurp(fname)
			except:
				print(f"Cannot open file {fname}")
		else:
			print(ai.system_message)
	elif usertext.startswith("-r"):
		if len(usertext) > 2:
			ai.system_message = usertext[2:].strip()
		else:
			print(ai.system_message)
	elif usertext.startswith("-L"):
		print(ai.messages)
	elif usertext.startswith("-f"):
		text = usertext[2:].strip()
		try:
			res = slurp(text)
			ai.chat(res)
		except:
			print("Cannot load file", file=sys.stderr)
	elif usertext.startswith("-i"):
		text = usertext[2:].strip()
		words = text.split(" ", 1)
		res = slurp(words[0])
		if len(words) > 1:
			que = words[1]
		else:
			que = input("[Query]> ")
		tag = "CODE" # INPUT , TEXT, ..
		#r2ai.chat("Q: " + que + ":\n["+tag+"]\n"+ res+"\n[/"+tag+"]\n")
		ai.chat(f"{que}:\n```\n{res}\n```\n")
#ai.chat(f"{que}:\n[{tag}]\n{res}\n[/{tag}]\n")
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
			que = input("[Query]> ")
		tag = "```\n" # TEXT, INPUT ..
		ai.chat(f"{que}:\n{tag}\n{res}\n{tag}\n")
	elif usertext[0] == "!":
		os.system(usertext[1:])
	elif usertext[0] == ".":
		try:
			file = slurp(usertext[1:].strip())
			exec(file, globals())
		except:
			traceback.print_exc()
			pass
	elif usertext[0] == ":":
		if r2 is None:
			print("r2 is not available")
		else:
			print(r2_cmd(usertext[1:]))
	elif usertext.startswith("-"):
		print("Unknown flag. See 'r2ai -h' for help")
	else:
		ai.chat(usertext)

def r2ai_repl():
	oldoff = "0x00000000"
	olivemode = ai.env["chat.live"]
	ai.env["chat.live"] = "true"
	while True:
		prompt = "[r2ai:" + oldoff + "]> "
		if r2 is not None:
			off = r2_cmd("s").strip()
			if off == "":
				off = r2_cmd("s").strip()
			if len(off) > 5 and len(off) < 20:
				oldoff = off
		if ai.active_block is not None:
			#r2ai.active_block.update_from_message("")
			ai.end_active_block()
		try:
			usertext = input(prompt).strip()
		except:
			break
		try:
			if ai.env["chat.bubble"] == "true":
				if usertext.startswith("-"):
					if runline(usertext) == "q":
						break
				else:
					bubble.query(usertext)
					bubble.response_begin()
					if runline(usertext) == "q":
						break
					bubble.response_end()
			else:
				if runline(usertext) == "q":
					break
		except:
			traceback.print_exc()
			continue
		readline.write_history_file(R2AI_HISTFILE)
	ai.env["chat.live"] = olivemode

try:
	lines = slurp(R2AI_RCFILE)
	for line in lines.split("\n"):
		if line.strip() != "":
			runline(line)
except:
	pass


### MAIN ###
if have_r2pipe:
	try:
		if "R2PIPE_IN" in os.environ.keys():
			r2 = r2pipe.open()
			within_r2 = True
		else:
			file = "/bin/ls"
			for arg in sys.argv[1:]:
				if arg.startswith("/"):
					file = arg
			r2 = r2pipe.open(file)
	except:
		traceback.print_exc()

if have_rlang:
	def r2ai_rlang_plugin(unused_but_required_argument):
		def _call(s):
			if s == "r2ai":
				print(help_message)
			elif s.startswith("r2ai"):
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
elif len(sys.argv) > 1:
#	ai.live_mode = False
	for arg in sys.argv[1:]:
		if not arg.startswith("/"):
			runline(arg)
		if arg == "-h" or arg == "-v":
			sys.exit(0)
	r2ai_repl()
elif not within_r2 and have_r2pipe:
	r2ai_repl()
else:
	r2ai_repl()
