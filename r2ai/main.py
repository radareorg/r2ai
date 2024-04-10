#!/usr/bin/env python3

import os
import sys
import time
import builtins
import traceback

def __main__():
    print("Hello maiN")
os.environ["TOKENIZERS_PARALLELISM"]="false"

try:
	r2aihome = os.path.dirname(os.readlink(__file__))
	sys.path.append(r2aihome)
	print(r2aihome)
	# if available
	sys.path.append(f"{r2aihome}/../vectordb")
except:
	pass

# run `make vectordb` because pip install vectordb2 is too old
sys.path.append(f"vectordb")

OPENAI_KEY = ""
try:
	if "HOME" in os.environ:
		from r2ai.utils import slurp
		apikey = slurp(os.environ["HOME"] + "/.r2ai.openai-key").strip()
		os.environ["OPENAI_API_KEY"] = apikey
		print("[R2AI] OpenAI key loaded from ~/.r2ai.openai-key")
except:
	pass

r2 = None
r2_file = None
have_rlang = False
have_r2pipe = False
within_r2 = False
print = print
if "R2CORE" in os.environ:
	within_r2 = True
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
if not have_rlang and not have_r2pipe and sys.argv[0] != 'main.py' and os.path.exists("venv/bin/python"):
	os.system("venv/bin/python main.py")
	sys.exit(0)

if "R2PIPE_IN" in os.environ.keys():
	try:
		import r2pipe
		have_r2pipe = True
	except:
		pass
### MAIN ###
ai = None
if have_r2pipe and not have_rlang:
	try:
		if "R2PIPE_IN" in os.environ.keys():
			r2 = r2pipe.open()
			within_r2 = True
		else:
			file = "/bin/ls"
			for arg in sys.argv[1:]:
				if arg.startswith("/"):
					file = arg
			r2_file = file
	except:
		traceback.print_exc()

def run_rcfile():
	global ai
	try:
		lines = slurp(R2AI_RCFILE)
		from r2ai.interpreter import Interpreter
		for line in lines.split("\n"):
			if line.strip() != "":
				if ai is None:
					ai = Interpreter()
				runline(ai, line)
	except:
		pass
	if ai is None:
		from r2ai.interpreter import Interpreter
		ai = Interpreter()

rcfile_loaded = False
def run_rcfile_once():
	global rcfile_loaded
	if rcfile_loaded == False:
		run_rcfile()
		rcfile_loaded = True

if have_rlang:
	from r2ai.repl import runline, r2ai_repl, help_message
	if have_r2pipe:
		r2ai_repl(ai)
		os.exit(0)
	def r2ai_rlang_plugin(unused_but_required_argument):
		global ai
		def _call(s):
			if not s.startswith("r2ai"):
				return False
			try:
				run_rcfile_once()
				if len(s) == 4:
					builtins.print(help_message)
				else:
					usertext = s[4:].strip()
					runline(ai, usertext)
			except Exception as e:
				builtins.print(e)
				traceback.print_exc()
			return True

		return {
			"name": "r2ai",
			"license": "MIT",
			"desc": "run llama language models inside r2",
			"call": _call,
		}
	r2lang.plugin("core", r2ai_rlang_plugin)
else:
	from r2ai.repl import runline, r2ai_repl
	from r2ai.utils import slurp
	run_rcfile()
	if len(sys.argv) > 1:
		for arg in sys.argv[1:]:
			if arg.endswith(".py"):
				exec(slurp(arg), globals())
				sys.stderr.close()
				sys.exit(0)
			elif not arg.startswith("/"):
				runline(ai, arg)
			if arg == "-h" or arg == "-v":
				sys.exit(0)
			elif arg == "-repl":
				r2ai_repl(ai)
	elif not within_r2:
		r2ai_repl(ai)
	elif have_r2pipe:
		r2ai_repl(ai)
	else:
		print("r2ai plugin cannot be loaded. Run `r2pm -ci rlang-python`")
