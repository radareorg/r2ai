import os
import logging
from rich.logging import RichHandler
from .config import Config

VERSION = "0.8.2"

# 0 NOTSET, 1 DEBUG, 2 INFO, 3 WARNING, 4 ERROR, 5 CRITICAL; multipied by 10
LOG_LEVEL = int(os.environ.get('R2AI_LOG', '2')) * 10
LOG_FILE = os.environ.get('R2AI_LOGFILE', None)
CONFIG = Config()

for tag in ["httpx", "openai", "httpcore"]:
    _logger = logging.getLogger(tag)
    _logger.setLevel(logging.CRITICAL)
    _logger.propagate = False  # Disable child loggers too

handlers = [RichHandler()]
if LOG_FILE:
    handlers.append(logging.FileHandler(LOG_FILE))

LOGGER = logging.getLogger(__name__)
logging.basicConfig(format="%(name)s - %(levelname)s - %(message)s",
                    handlers=handlers)
LOGGER.setLevel(LOG_LEVEL)