import sys
from .models import models, mainmodels
sys.modules["r2ai"].models = models
sys.modules["r2ai"].mainmodels = mainmodels
VERSION = "0.7.0"
