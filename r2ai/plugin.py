"""Entrypoint for the r2ai plugin and repl."""

import builtins
import traceback
import r2lang
from r2ai.main import r2ai_singleton, run_rcfile_once, runline, help_message

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

r2lang.plugin("core", r2ai_rlang_plugin)