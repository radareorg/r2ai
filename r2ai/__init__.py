from .models import models
import sys

sys.modules["r2ai"].models = models
VERSION = "0.3.0"
