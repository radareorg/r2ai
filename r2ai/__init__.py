import sys
from .models import models
sys.modules["r2ai"].models = models
VERSION = "0.5.0"
