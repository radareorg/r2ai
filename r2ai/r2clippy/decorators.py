from functools import wraps

from r2ai.interpreter_base import BaseInterpreter
from r2ai.r2clippy.models import get_model_by_str
from r2ai.r2clippy.utils import context_from_msg

# TODO: context for each model

def context(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        interpreter = None
        for arg in args:
            if isinstance(arg, BaseInterpreter):
                interpreter = arg
                break
        if interpreter:
            chat_context = ""
            lastmsg = interpreter.messages[-1]
            chat_context = context_from_msg(lastmsg)
            if chat_context:
                interpreter.messages.append(
                    {
                        "role": "user",
                        "content": chat_context
                    }
                )
        return func(*args, **kwargs)
    return wrapper

# TODO: system message for each model


def system_message(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        interpreter = None
        for arg in args:
            if isinstance(arg, BaseInterpreter):
                interpreter = arg

        if interpreter:
            if len(interpreter.messages) == 1:
                interpreter.messages.insert(0,
                                            {
                                                "role": "system",
                                                "content": get_model_by_str(interpreter.model).system_prompt
                                            })
        return func(*args, **kwargs)
    return wrapper
