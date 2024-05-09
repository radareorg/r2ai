import builtins
from r2ai.models import set_default_model
from .utils import slurp
import traceback
have_readline = False
from .const import R2AI_HISTFILE, R2AI_HOMEDIR, R2AI_RCFILE, R2AI_USERDIR
import r2ai
import sys
import os

from .tab import tab_init, tab_hist, tab_write, tab_evals

tab_init()

print_buffer = ""
ais = {}
autoai = None
from .pipe import have_rlang, r2lang, r2singleton
r2 = r2singleton()

def r2_cmd(x):
  global have_rlang, ai, r2, r2_file
  have_rlang = True
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

# TODO : move into r2ai/http.py
def start_http_server(ai):
  import http.server
  import socketserver

  PORT = 8000
  BASEPATH = ""

  Handler = http.server.SimpleHTTPRequestHandler

  class SimpleHTTPRequestHandler(Handler):
    def do_GET(self):
      self.send_response(404)
      self.end_headers()
      self.wfile.write(bytes(f'Invalid request. Use POST and /{BASEPATH}', 'utf-8'))
    def do_POST(self):
      if self.path.startswith(BASEPATH):
        content_length = int(self.headers['Content-Length'])
        msg = self.rfile.read(content_length).decode('utf-8')
        self.send_response(200)
        self.end_headers()
        res = runline2(ai, msg)
        self.wfile.write(bytes(f'{res}','utf-8'))
      else:
        self.send_response(404)
        self.end_headers()
        self.wfile.write(bytes(f'Invalid request. Use {BASEPATH}'))

  Handler.protocol_version = "HTTP/1.0"
  server = socketserver.TCPServer(("", PORT), SimpleHTTPRequestHandler)
  server.allow_reuse_address = True
  server.allow_reuse_port = True
  print("Serving at port", PORT)
  server.serve_forever()

help_message = """Usage: r2ai [-option] ([query] | [script.py])
 r2ai . [file]          interpret r2ai script with access to globals
 r2ai ..([script])      list or run r2ai user script
 r2ai :aa               run a r2 command
 r2ai ' [prompt]        auto mode; query LLM that can interact with r2
 r2ai !ls               run a system command
 r2ai -a                query with audio voice
 r2ai -A                enter the voice chat loop
 r2ai -k                clear the screen
 r2ai -c [cmd] [query]  run the given r2 command with the given query
 r2ai -e [k[=v]]        set environment variable
 r2ai -f [file]         load file and paste the output
 r2ai -h                show this help (same as ?)
 r2ai -H ([var])        show path variables like it's done in r2 -H
 r2ai -i [file] ([q])   load the file contents and prompt it with the given optional query
 r2ai -m [file/repo]    select model from huggingface repository or local file
 r2ai -M                list supported and most common models from hf
 r2ai -MM               shorter list of models
 r2ai -n [num]          select the nth language model
 r2ai -q                quit/exit/^C
 r2ai -L                show chat logs (See -Lj for json)
 r2ai -repl             enter the repl (only when running via r2pipe)
 r2ai -r [sysprompt]    define the role of the conversation
 r2ai -r2               enter the r2clippy assistant mode
 r2ai -rf [doc/role/.f] load contents of a file to define the role
 r2ai -R                reset the chat conversation context
 r2ai -t [temp]         from 0.0001 to 10 your scale to randomness in my replies
 r2ai -v                show r2ai version (same as ?V)
 r2ai -w                start webserver (curl -D hello http://localhost:8000)"""

def myprint(msg, file=None):
  global print_buffer
  builtins.print(msg)
  print_buffer += msg

def runline2(ai, usertext):
  global print
  global print_buffer
  ai.print = myprint
  chat_live = ai.env["chat.live"]
  ai.env["chat.live"] = "false"
  print = myprint
  runline(ai, usertext)
  ai.env["chat.live"] = chat_live
  res = print_buffer
  print_buffer = ""
  return f"{res}\n"

def runplugin(ai, arg):
  r2ai_plugdir = ai.env["user.plugins"]
  if arg != "":
    for plugdir in [R2AI_USERDIR, r2ai_plugdir]:
      script_path = f"{plugdir}/{arg}.py"
      if os.path.isfile(script_path):
        runline(ai, f". {script_path}")
        return
    print("Script not found", file=sys.stderr)
    return
  try:
    # print("-e user.plugins = " + r2ai_plugdir)
    for plugdir in [R2AI_USERDIR, r2ai_plugdir]:
      files = os.listdir(plugdir)
      for file in files:
        if file.endswith(".py"):
          print(file.replace(".py", ""))
  except:
    pass

def r2ai_version():
  import sys
  import llama_cpp
  print("python: " + sys.version)
  print("llama: " + llama_cpp.__version__)
  print("r2ai: " + r2ai.VERSION)

def r2ai_vars(ai, arg):
  vs = {
    "R2AI_USERDIR": R2AI_USERDIR,
    "R2AI_PLUGDIR": ai.env["user.plugins"],
    "R2AI_HOMEDIR": R2AI_HOMEDIR,
    "R2AI_RCFILE": R2AI_RCFILE,
    "R2AI_HISTFILE": R2AI_HISTFILE
  }
  if arg != "":
    if arg in vs.keys():
      print(vs[arg])
    else:
      print("Unknown key", file=sys.stderr)
  else:
    for k in vs.keys():
      print(k)

def runline(ai, usertext):
  global print
  global autoai
  if ai == None:
    ai = ais[0];
  usertext = usertext.strip()
  if usertext == "" or usertext.startswith("#"):
    return
  if usertext == "q":
    return "q"
  if usertext.startswith("-H"):
    try:
      return r2ai_vars(ai, usertext[2:].strip())
    except:
      traceback.print_exc()
  if usertext.startswith("?V") or usertext.startswith("-v"):
    print(r2ai.VERSION)
    r2ai_version()
  elif usertext.startswith("?") or usertext.startswith("-h"):
    print(help_message)
  elif usertext.startswith("clear") or usertext.startswith("-k"):
    print("\x1b[2J\x1b[0;0H\r")
  elif usertext.startswith("-MM"):
    print(r2ai.mainmodels().strip())
  elif usertext.startswith("-M"):
    print(r2ai.models().strip())
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
      print(ai.env["llm.temperature"])
    else:
      ai.env["llm.temperature"] = usertext[2:].strip()
  elif usertext == "-A":
    from r2ai.voice import stt
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
    from r2ai.voice import stt
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
  elif usertext == "-repl":
    if have_rlang:
      r2ai_repl(ai)
    else:
      print("r2ai -repl # only works when running as an radare2 plugin")
  elif usertext == "-r2":
    ai.env["data.use"] = "true"
    ai.env["data.hist"] = "true"
    ai.env["data.path"] = f"{R2AI_HOMEDIR}/doc/"
    ai.env["chat.bubble"] = "true"
    runline(ai, f"-rf {R2AI_HOMEDIR}/doc/role/r2clippy.txt")
  elif usertext.startswith("-e"):
    if len(usertext) == 2:
      for k in ai.env.keys():
        v = ai.env[k]
        print(f"-e {k}={v}")
    elif usertext.endswith("."):
      kp = usertext[2:].strip()
      for k in ai.env.keys():
        if k.startswith(kp):
          v = ai.env[k]
          print(f"-e {k}={v}")
    else:
      line = usertext[2:].strip().split("=")
      k = line[0]
      if len(line) > 1:
        v = line[1]
        if v == "":
          ai.env[k] = ""
        elif k in ai.env:
          ai.env[k] = v
        else:
          print("Invalid config key", file=sys.stderr)
      else:
        try:
          print(ai.env[k])
        except:
          print("Invalid config key", file=sys.stderr)
          pass
  elif usertext.startswith("-w"):
    start_http_server(ai)
  elif usertext.startswith("-s"):
    r2ai_repl(ai)
  elif usertext.startswith("-rf"):
    if len(usertext) > 2:
      fname = usertext[3:].strip()
      try:
        ai.system_message = slurp(fname)
      except:
        print(f"Cannot open file {fname}", file=sys.stderr)
    else:
      print(ai.system_message)
  elif usertext.startswith("-r"):
    if len(usertext) > 2:
      ai.system_message = usertext[2:].strip()
    else:
      print(ai.system_message)
  elif usertext.startswith("-Lj"):
    print(ai.messages)
  elif usertext.startswith("-L"):
    for msg in ai.messages:
      #print(f"<{msg['role']}> {msg['content']}")
      print(f"\x1b[33m<{msg['role']}>\x1b[0m {msg['content']}")
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
      # tag = "CODE" # INPUT , TEXT, ..
      # r2ai.chat("Q: " + que + ":\n["+tag+"]\n"+ res+"\n[/"+tag+"]\n")
      ai.chat(f"{que}:\n```\n{res}\n```\n")
    else:
      que = input("[Query]> ")
      ai.chat(res)
  elif usertext.startswith("-n"):
    if len(ais.keys()) == 0:
      ais[0] = ai
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
  elif usertext.startswith("-c"):
    words = usertext[2:].strip().split(" ", 1)
    res = r2_cmd(words[0])
    que = ""
    try:
      if len(words) > 1:
        que = words[1]
      else:
        que = input("[Query]> ")
    except:
      print("")
      return
    tag = "```\n" # TEXT, INPUT ..
    ai.chat(f"{que}:\n{tag}\n{res}\n{tag}\n")
  elif usertext[0] == "!":
    os.system(usertext[1:])
  elif usertext[0] == ".":
    if len(usertext) > 1 and usertext[1] == ".": # ".." - run user plugins
      runplugin(ai, usertext[2:].strip())
      return
    try:
      filename = usertext[1:].strip()
      file = slurp(filename)
      if filename.endswith(".py"):
        exec(file, globals())
      else:
        for line in file.split("\n"):
          runline(ai, line)
    except Exception as e:
      # traceback.print_exc()
      print(e)
      pass
  elif usertext.startswith("' "):
    if not autoai:
      autoai = r2ai.interpreter.Interpreter()
      autoai.auto_run = True
    autoai.chat(usertext[2:])
  elif usertext[0] == ":":
    if r2 is None:
      print("r2 is not available", file=sys.stderr)
    else:
      print(r2_cmd(usertext[1:]))
  elif usertext.startswith("-"):
    print("Unknown flag. See 'r2ai -h' for help", file=sys.stderr)
  else:
    ai.chat(usertext)

def r2ai_repl(ai):
  from r2ai import bubble
  tab_evals(ai.env.keys())
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
          if runline(ai, usertext) == "q":
            break
        else:
          bubble.query(usertext)
          bubble.response_begin()
          if runline(ai, usertext) == "q":
            break
          bubble.response_end()
      else:
        if runline(ai, usertext) == "q":
          break
    except:
      traceback.print_exc()
      continue
    tab_write()
  ai.env["chat.live"] = olivemode
