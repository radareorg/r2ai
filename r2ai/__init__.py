from .models import models
from .interpreter import Interpreter
import sys

sys.modules["r2ai"].models = models
VERSION = "0.4.0"
