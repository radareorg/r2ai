"""File containing constants."""
import os

join = os.path.join

R2AI_HOMEDIR = os.path.dirname(os.path.realpath(__file__ + "/.."))
R2AI_HISTFILE = "r2ai.history.txt" # windows path
R2AI_RCFILE = "r2ai.txt"
if "HOME" in os.environ:
    R2AI_HISTFILE = join(os.environ["HOME"], ".r2ai.history")
    R2AI_RCFILE = join(os.environ["HOME"], ".r2ai.rc")
R2AI_USERDIR = join(os.environ["HOME"], ".r2ai.plugins")
