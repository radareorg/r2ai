from .. import LOGGER
from .ais.ai_openai import chat as openai_chat
from .functions import get_ai_tools
from .models import parse_model_str

storage = {}


def chat(interpreter):
    model = parse_model_str(interpreter.model)
    fn = None
    if model.id in auto_chat_handlers.get(model.platform):
        if model.uri:
            interpreter.api_base = model.uri
        fn = auto_chat_handlers[model.platform][model.id]
    elif "default" in auto_chat_handlers.get(model.platform, {}):
        if model.uri:
            interpreter.api_base = model.uri
        fn = auto_chat_handlers[model.platform]["default"]
    if not fn:
        LOGGER.error("Model %s:%s is not currently supported in auto mode")
        return
    return fn(interpreter)


def chat_open_ai():
    pass


auto_chat_handlers = {
    "openai": {
        "default": openai_chat
    },
    "openapi": {
        "default": openai_chat
    }
}
