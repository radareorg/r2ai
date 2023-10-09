from .interpreter import Interpreter
import sys

# This is done so when users `import interpreter`,
# they get an instance of interpreter:
# **This is a controversial thing to do,** lets say is wrong and only allows us to have 1 instance
# because perhaps modules ought to behave like modules.

#sys.modules["r2ai"] = Interpreter()
#sys.modules["r2ai"].VERSION = "0.2.1"
VERSION = "0.2.1"
