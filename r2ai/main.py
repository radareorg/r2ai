#!/usr/bin/env python3

import os
import sys
import builtins
import traceback
import appdirs

from r2ai.repl import r2ai_singleton
from r2ai.utils import slurp
from r2ai.repl import runline, r2ai_repl, help_message

from r2ai.pipe import open_r2
from .const import R2AI_RCFILE

OPENAI_KEY = ""
HAVE_RLANG = False
HAVE_R2PIPE = False
RCFILE_LOADED = False
within_r2 = False

if "R2CORE" in os.environ:
    within_r2 = True

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

# TODO: see repl.run_script as replacement
def run_rcfile():
    try:
        lines = slurp(R2AI_RCFILE)
        
        for line in lines.split("\n"):
            if line.strip() != "":
                if ai is None:
                    ai = r2ai_singleton()
                runline(ai, line)
    except Exception:
        pass
    if ai is None:
        ai = r2ai_singleton()

def run_rcfile_once():
    global RCFILE_LOADED
    if not RCFILE_LOADED:
        run_rcfile()
        RCFILE_LOADED = True


def main(args, commands, dorepl=True):
    global within_r2

    os.environ["TOKENIZERS_PARALLELISM"] = "false"

    try:
        r2aihome = os.path.dirname(os.path.realpath(__file__))
        sys.path.append(r2aihome)
        # if available
        sys.path.append(
            os.path.join(r2aihome, "..", "vectordb")
        )
    except Exception:
        traceback.print_exc()

    home_dir = os.path.expanduser("~")
    # create symlink if it doesnt exist
    try:
        dst = os.path.join(home_dir, ".r2ai.models")
        udd = appdirs.user_data_dir("r2ai")
        src = os.path.join(udd, "models")
        if not os.path.exists(dst):
            os.symlink(src, dst)
    except Exception:
        traceback.print_exc()

    r2_openai_file = os.path.join(home_dir, ".r2ai.openai-key")
    if os.path.isfile(r2_openai_file):
        apikey = slurp(r2_openai_file).strip()
        os.environ["OPENAI_API_KEY"] = apikey
        print("[R2AI] OpenAI API key loaded from ~/.r2ai.openai-key", file=sys.stderr)


    r2_anthropic_file = os.path.join(home_dir, ".r2ai.anthropic-key")
    if os.path.isfile(r2_anthropic_file):
        apikey = slurp(r2_anthropic_file).strip()
        os.environ["ANTHROPIC_API_KEY"] = apikey
        print("[R2AI] Anthropic API key loaded from ~/.r2ai.anthropic-key", file=sys.stderr)
    
    ai = r2ai_singleton()
    if "R2PIPE_IN" in os.environ:
        open_r2(None)
        within_r2 = True
    elif args.bin:
        open_r2(vars(args)["bin"], flags=["-2"])

    if commands is not None:
        for c in commands:
            if c.startswith("_"):
                runline(ai, "-" + c[1:])
            else:
                runline(ai, c)
    if dorepl:
        r2ai_repl(ai)
    # elif HAVE_RLANG and HAVE_R2PIPE:
    #     r2ai_repl(ai)
    #     os.exit(0)

    #     r2lang.plugin("core", r2ai_rlang_plugin)

    # else:
    #     if "R2CORE" in os.environ:
    #         print("[R2AI] Please: r2pm -ci rlang-python")
    #         sys.exit(0)
        
    #     run_rcfile()
    #     if len(sys.argv) > 1:
    #         for arg in sys.argv[1:]:
    #             if arg.endswith(".py"):
    #                 exec(slurp(arg), globals())
    #                 sys.stderr.close()
    #                 sys.exit(0)
    #             elif not arg.startswith("/"):
    #                 runline(ai, arg)
    #             if arg == "-h" or arg == "-v":
    #                 sys.exit(0)
    #             elif arg == "-repl":
    #                 r2ai_repl(ai)
    #     elif not within_r2:
    #         r2ai_repl(ai)
    #     elif HAVE_R2PIPE:
    #         r2ai_repl(ai)
    #     else:
    #         print("r2ai plugin cannot be loaded. Run `r2pm -ci rlang-python`")
