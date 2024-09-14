from r2ai.r2clippy.chat import auto_chat
from r2ai.interpreter_base import BaseInterpreter

Interpreter = None

def chat(interpreter: BaseInterpreter):
    Interpreter = interpreter
    auto_chat(Interpreter)