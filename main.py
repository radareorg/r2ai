"""Entrypoint for the r2ai plugin and repl."""

import runpy
import sys
import os

if "R2AI" in os.environ:
    print("Cant load r2ai r2 plugin from inside r2ai")
    sys.exit(0)
r2aihome = os.path.dirname(__file__)
try:
    r2aihome = os.path.dirname(os.readlink(__file__))
except (OSError, FileNotFoundError):
    pass
sys.path.insert(0, r2aihome)
os.environ["R2AI"] = "1"
if "VIRTUAL_ENV" in os.environ or "R2CORE" in os.environ:
    runpy.run_path(os.path.join(r2aihome, 'r2ai', 'main.py'))
else:
    ARGS = " ".join(sys.argv[1:])
    os.system(f"cd {r2aihome}; ./r2ai.sh {ARGS}")
