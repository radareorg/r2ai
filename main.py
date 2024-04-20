import runpy
import sys
import os

r2aihome = os.path.dirname(__file__)
try:
  r2aihome = os.path.dirname(os.readlink(__file__))
except:
  pass
sys.path.insert(0, r2aihome)
if "VIRTUAL_ENV" in os.environ or "R2CORE" in os.environ:
  runpy.run_path(os.path.join(r2aihome, 'r2ai', 'main.py'))
else:
  os.system(f"cd {r2aihome}; ./run-venv.sh {" ".join(sys.argv[1:])}");
