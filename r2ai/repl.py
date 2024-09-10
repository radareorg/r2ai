import builtins
from .models import set_default_model, list_downloaded_models, delete_downloaded_model, models, mainmodels
from .utils import slurp
from .large import Large
import traceback
from .const import R2AI_HISTFILE, R2AI_HOMEDIR, R2AI_RCFILE, R2AI_USERDIR
from .web import start_http_server
import r2ai
from datetime import datetime
import sys
import os

from .tab import tab_init, tab_hist, tab_write, tab_evals
from .interpreter import Interpreter
from .pipe import have_rlang, r2lang, r2singleton
from r2ai import bubble, LOGGER

tab_init()

print_buffer = ""
ais = []
autoai = None
r2 = r2singleton()

def r2ai_singleton():
    global ais
    if len(ais) == 0:
        ai = Interpreter()
        ais.append(R2AI(ai))
    return ais[0].ai

def r2_cmd(x):
    global have_rlang, ai, r2
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

help_message = """Usage: r2ai [-option] ([query] | [script.py])
 r2ai . [file]          interpret r2ai script with access to globals
 r2ai ..([script])      list or run r2ai user script
 r2ai :aa               run a r2 command
 r2ai ' [prompt]        auto mode; query LLM that can interact with r2
 r2ai ?e [msg]          echo a message
 r2ai ?t [query]        run an query and show it's timing
 r2ai !ls               run a system command
 r2ai -a                query with audio voice
 r2ai -A                enter the voice chat loop
 r2ai -k                clear the screen
 r2ai -c [cmd] [query]  run the given r2 command with the given query
 r2ai -e [k[=v]]        set environment variable
 r2ai -ed               launch user.editor with ~/.r2ai.rc
 r2ai -f [file]         load file and paste the output
 r2ai -h                show this help (same as ?)
 r2ai -H ([var])        show path variables like it's done in r2 -H
 r2ai -i [file] ([q])   load the file contents and prompt it with the given optional query
 r2ai -j [query]        convert the user prompt into a meaningful json
 r2ai -m [file/repo]    select model from huggingface repository or local file
 r2ai -m-[repo/model]   delete a local downloaded model (see -mm for listing them)
 r2ai -mm               list all downloaded models
 r2ai -M                shorter list of models
 r2ai -MM               list supported and most common models from hf
 r2ai -n [num]          select the nth language model
 r2ai -q                quit/exit/^C
 r2ai -L                show chat logs (See -Lj for json)
 r2ai -L-[N]            delete the last (or N last messages from the chat history)
 r2ai -repl             enter the repl (only when running via r2pipe)
 r2ai -r [sysprompt]    define the role of the conversation
 r2ai -r2               enter the r2clippy assistant mode
 r2ai -rf [doc/role/.f] load contents of a file to define the role
 r2ai -R                reset the chat conversation context
 r2ai -t [temp]         from 0.0001 to 10 your scale to randomness in my replies
 r2ai -v                show r2ai version (same as ?V)
 r2ai -w ([port])       start webserver (curl -D hello http://localhost:8000)
 r2ai -W ([port])       start webserver in background
 r2ai -V (num)          set log level for this session
                        0: NOTSET, 1: DEBUG, 2: INFO,
                        3: WARNING, 4: ERROR, 5: CRITICAL
r2ai -V                 get current log level"""

def myprint(msg, file=None):
    global print_buffer
    builtins.print(msg)
    print_buffer += str(msg)

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
    except Exception:
      pass

def r2ai_version():
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

# copypasta from main.run_rcfile . todo avoid dup code
def run_script(ai, script):
    try:
        lines = slurp(script)
        for line in lines.split("\n"):
            if line.strip() != "":
                runline(ai, line)
    except Exception:
        pass

class R2AI:
    def __init__(self,ai):
        self.ai = ai

    def cmd(self, x):
        return runline2(self.ai, x)

def slurp_until(endword):
    text = ""
    while True:
      line = sys.stdin.readline()
      if line.strip() == endword:
          break
      text += line
    return text

def runline(ai, usertext):
    global print
    global autoai
    if ai == None:
        ai = ais[0].ai
    usertext = usertext.strip()
    if usertext == "" or usertext.startswith("#"):
        return
    if usertext == "q":
        return "q"
#    pipepos = usertext.find("|")
#    if pipepos != -1:
#        usertext = usertext[0:pipepos - 1]
#        print("TODO: | pipes are not yet implemented in r2ai", file=sys.stderr)
#    redipos = usertext.find(">")
#    if redipos != -1:
#        usertext = usertext[0:redipos - 1]
#        print("TODO: > redirections are not yet implemented in r2ai", file=sys.stderr)
    if usertext.startswith("-H"):
        try:
            return r2ai_vars(ai, usertext[2:].strip())
        except Exception:
            traceback.print_exc()
    if usertext.startswith("?V") or usertext.startswith("-v"):
        r2ai_version()
    elif usertext.startswith("<<"):
        newline = slurp_until(usertext[2:])
        return runline(ai, newline)
    elif usertext.startswith("?e"):
        print(usertext[2:].strip())
    elif usertext.startswith("?t"):
        tstart = datetime.now()
        runline(ai, usertext[2:].strip())
        tend = datetime.now()
        print(tend - tstart)
    elif usertext.startswith("?") or usertext.startswith("-h") or usertext.startswith("-?"):
        print(help_message)
    elif usertext.startswith("clear") or usertext.startswith("-k"):
        print("\x1b[2J\x1b[0;0H\r")
    elif usertext.startswith("-MM"):
        print(models().strip())
    elif usertext.startswith("-M"):
        print(mainmodels().strip())
    elif usertext.startswith("-mm"):
        list_downloaded_models()
    elif usertext.startswith("-m-"):
        delete_downloaded_model(usertext[2:])
    elif usertext.startswith("-m"):
        words = usertext.split(" ")
        if len(words) > 1:
            if ai.model is not words[1]:
                ai.llama_instance = None
            ai.model = words[1]
            ai.env["llm.model"] = ai.model
            set_default_model(ai.model)
        else:
            print(ai.model)
    elif usertext == "reset" or usertext.startswith("-R"):
        ai.reset()
    elif usertext.startswith("-j"):
        q = usertext[2:].strip()
        query = f"Please respond using ONLY in JSON with the following fields if relevant: topic, array of key words, location, url, name, description, target, amounts and other details if necessary without providing any response. Question: \"{q}\""
        ai.chat(query)
    elif usertext.startswith("-t"):
        if usertext == "-t":
            print(ai.env["llm.temperature"])
        else:
            ai.env["llm.temperature"] = usertext[2:].strip()
    elif usertext == "-A":
        from .voice import stt
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
        from .voice import stt
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
    elif usertext.startswith("-ed"):
        editor = "vim" # Defaults to the only real editor
        if ai.env["user.editor"] != "":
            editor = ai.env["user.editor"]
        elif "EDITOR" in os.environ:
            editor = os.environ["EDITOR"]
        os.system(f"{editor} {R2AI_RCFILE}")
        print("Reload? (y/N)")
        if input() == "y":
            run_script(ai, R2AI_RCFILE)
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
                    if k.startswith("llm."):
                        ai.llama_instance = None
                else:
                    print("Invalid config key", file=sys.stderr)
            else:
                try:
                    print(ai.env[k])
                except Exception:
                    print("Invalid config key", file=sys.stderr)
                    pass
    elif usertext.startswith("-l"):
        try:
            l = Large(ai)
            t = slurp("doc/samples/qcw.txt")
            print(l.summarize_text(t))
        except Exception:
            traceback.print_exc()
        sys.exit(0)
    elif usertext.startswith("-W"):
        if len(usertext) > 2:
            port = int(usertext[2:])
            if port > 0:
                runline2(ai, f"-e http.port={port}")
        start_http_server(ai, runline2, True)
    elif usertext.startswith("-w"):
        if len(usertext) > 2:
            port = int(usertext[2:])
            if port > 0:
                runline2(ai, f"-e http.port={port}")
        start_http_server(ai, runline2, False)
    elif usertext.startswith("-s"):
        ai.runline2 = runline2
        r2ai_repl(ai)
    elif usertext.startswith("-rf"):
        if len(usertext) > 2:
            fname = usertext[3:].strip()
            try:
                ai.system_message = slurp(fname)
            except Exception:
                print(f"Cannot open file {fname}", file=sys.stderr)
        else:
            print(ai.system_message)
    elif usertext.startswith("-r"):
        if len(usertext) > 2:
            ai.system_message = usertext[2:].strip()
        else:
            print(ai.system_message)
    elif usertext.startswith("-L-"):
        try:
            amount = int(usertext[3:])
            if amount < 1:
                amount = 1
        except Exception:
            amount = 1
        try:
            for i in range(amount):
                ai.messages.pop() # delete user message
                ai.messages.pop() # delete assistant message
        except Exception:
            pass
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
        except Exception:
            print("Cannot load file", file=sys.stderr)
    elif usertext.startswith("-i"):
        text = usertext[2:].strip()
        if text == "":
            print("Usage: r2ai -i [file] [question]")
            return
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
        if len(ais) == 0:
            ais.append(R2AI(ai))
        if usertext == "-n":
            pos = 0
            for a in ais:
                model = a.ai.model
                print(f"{pos}  - {model}")
                pos += 1
        else:
            index = int(usertext[2:])
            if index < len(ais):
                ai = ais[index].ai
            else:
                ai0 = Interpreter()
                ai0.model = ai.model
                ais.append(R2AI(ai0))
    elif usertext.startswith("-c"):
        words = usertext[2:].strip().split(" ", 1)
        res = r2_cmd(words[0])
        que = ""
        try:
            if len(words) > 1:
                que = words[1]
            else:
                que = input("[Query]> ")
        except Exception:
            print("")
            return

        tag = "```\n" # TEXT, INPUT ..
        ai.chat(f"{que}:\n{tag}\n{res}\n{tag}\n")
    elif usertext[0] == "!":
        os.system(usertext[1:])
    elif usertext[0] == ".":
        #if len(usertext) > 1 and usertext[1] == ".": # ".." - run user plugins
        #    runplugin(ai, usertext[2:].strip())
        #    return
        try:
            filename = usertext[1:].strip()
            file = slurp(filename)
            if filename.endswith(".py"):
                exec(file, globals())
            else:
                for line in file.split("\n"):
                    runline(ai, line)
        except Exception:
            traceback.print_exc()

    elif usertext.startswith("' "):
        if not autoai:
            autoai = Interpreter()
            autoai.auto_run = True

        autoai.chat(usertext[2:])

    elif usertext[0] == ":":
        if r2 is None:
            print("r2 is not available", file=sys.stderr)
        else:
            builtins.print(r2_cmd(usertext[1:]))
    elif usertext.startswith("-V"):
        arguments = usertext.split()
        if len(arguments) > 1:
            LOGGER.setLevel(int(arguments[-1]) * 10)
        else:
            print("{0:.0f}".format(LOGGER.level / 10))
    elif usertext.startswith("-"):
        print("Unknown flag. See 'r2ai -h' for help", file=sys.stderr)
    else:
        ai.chat(usertext)

def r2ai_repl(ai):
    tab_evals(ai.env.keys())
    oldoff = r2_cmd("?vx $$").strip()
    if oldoff == "0x0" or oldoff == "":
        oldoff = "0x00000000"
    olivemode = ai.env["chat.live"]
    ai.env["chat.live"] = "true"
    while True:
        prompt = "[r2ai:" + oldoff + "]> "
        if os.name != "nt":
            prompt = f"\001\x1b[33m\002{prompt}" # \001\x1b[0m\002"
        if r2 is not None:
            off = r2_cmd("?vx $$").strip()
            if off == "":
                off = r2_cmd("?vx $$").strip()
            if len(off) > 5 and len(off) < 20:
                oldoff = off
        if ai.active_block is not None:
            # r2ai.active_block.update_from_message("")
            ai.end_active_block()
        try:
            usertext = input(prompt).strip()
            if os.name != "nt":
                builtins.print("\001\x1b[0m\002", end="")
        except EOFError:
            break
        except Exception:
            traceback.print_exc()
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
        except Exception:
            traceback.print_exc()
            continue
        tab_write()
    ai.env["chat.live"] = olivemode
