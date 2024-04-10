import runpy
import os
r2aihome = os.path.dirname(__file__) #os.readlink(__file__))
runpy.run_path(r2aihome + '/r2ai/main.py')
