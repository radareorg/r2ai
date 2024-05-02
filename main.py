"""Entrypoint for the r2ai plugin and repl."""

import runpy
import sys
import os

r2aihome = os.path.dirname(__file__)
try:
    r2aihome = os.path.dirname(os.readlink(__file__))
except (OSError, FileNotFoundError):
    pass
sys.path.insert(0, r2aihome)
if "VIRTUAL_ENV" in os.environ or "R2CORE" in os.environ:
    runpy.run_path(os.path.join(r2aihome, 'r2ai', 'main.py'))
else:
    ARGS = " ".join(sys.argv[1:])
    os.system(f"cd {r2aihome}; ./run-venv.sh {ARGS}")
