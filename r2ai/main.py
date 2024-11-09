#!/usr/bin/env python3

import os
os.environ["TRANSFORMERS_NO_ADVISORY_WARNINGS"] = "1"
import sys
import builtins
import traceback
import appdirs
import argparse

from r2ai.repl import r2ai_singleton
from r2ai.utils import slurp
from r2ai.repl import runline, r2ai_repl, help_message

from r2ai.pipe import open_r2, get_r2_inst
from r2ai.const import R2AI_RCFILE

OPENAI_KEY = ""
HAVE_RLANG = False
HAVE_R2PIPE = False
RCFILE_LOADED = False

def r2ai_rlang_plugin(unused_but_required_argument):
    ai = r2ai_singleton()
    def _call(s):
        if not s.startswith("r2ai"):
            return False
        try:
            run_rcfile_once(ai)
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
def run_rcfile(ai):
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

def run_rcfile_once(ai):
    global RCFILE_LOADED
    if not RCFILE_LOADED:
        run_rcfile(ai)
        RCFILE_LOADED = True


def main(args, commands, dorepl=True):

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
        pass
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

def massage_args(args):
    runrepl = True
    if args.command is None:
        args.command = []
    if args.webserver:
        args.command.append("-w")
    if args.eval:
        if args.eval == "default":
            args.command.append("-e")
            runrepl = False
        else:
            args.command.append(f"-e {args.eval}")
    if args.port:
        if args.port == "default":
            runrepl = False
            args.command.append("-e http.port")
        else:
            args.command.append(f"-e http.port={args.port}")
    if args.model:
        if args.model == "default":
            args.command.append("-mm")
            runrepl = False
        else:
            args.command.append(f"-m {args.model}")
    return runrepl, args

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("bin", nargs="?", type=str)
    parser.add_argument("-w", "--webserver", action="store_true",
        help="Start the r2ai webserver. Same as r2ai -c=-w")
    parser.add_argument("-p", "--port", type=str, nargs="?", const="default",
        help="Change listen port number")
    parser.add_argument("-e", "--eval", type=str, nargs="?", const="default",
        help="Change configuration variable")
    parser.add_argument("-m", "--model", type=str, nargs="?", const="default",
        help="Select model name")
    parser.add_argument("-c", "--command", action="append",
        help="Command to be executed. Can be passed multiple times.")
    runrepl, args = massage_args(parser.parse_args())
    main(args, args.command, runrepl)