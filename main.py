import runpy
import sys
import os

r2aihome = os.path.dirname(__file__) #os.readlink(__file__))
if "PYTHONPATH" in os.environ:
  os.environ["PYTHONPATH"] = r2aihome + ":" + os.environ["PYTHONPATH"]
else:
  os.environ["PYTHONPATH"] = r2aihome
if "VIRTUAL_ENV" in os.environ:
  runpy.run_path(os.path.join(r2aihome, 'r2ai', 'main.py'))
else:
  os.system("run-venv.sh");

#print(os.path.relpath('./r2ai/main.py', __file__))
#runpy.run_path(os.path.relpath('./r2ai/main.py', __file__))
