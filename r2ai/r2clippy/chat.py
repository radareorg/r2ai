
from r2ai import LOGGER
from r2ai.models import new_get_hf_llm
from r2ai.r2clippy.functions import get_ai_tools
from r2ai.r2clippy.models import parse_model_str
from r2ai.r2clippy.processors import process_streaming_response
from r2ai.r2clippy.decorators import system_message, context
from litellm import completion as litellm_completion
from r2ai.interpreter_base import BaseInterpreter
from r2ai.r2clippy.constants import LITELMM_PROVIDERS

from r2ai.r2clippy.utils.split_string import split_string_with_limit
from llama_cpp import Llama

def auto_chat(interpreter: BaseInterpreter):
    model = parse_model_str(interpreter.model)
    _auto_chat(interpreter, model)

@system_message
@context
def _auto_chat(interpreter: BaseInterpreter, model):
    call = True
    while call:
        extra_args = {} 
        completion = None
        response_wrapper = lambda r: r
        if model.platform not in LITELMM_PROVIDERS:
            if not interpreter.llama_instance:
                interpreter.llama_instance = new_get_hf_llm(interpreter, f"{model.platform}/{model.id}", (LOGGER.level / 10) == 1, int(interpreter.env["llm.window"]))
            interpreter.llama_instance.chat_format = interpreter.env["llm.chat_format"]
            completion = interpreter.llama_instance.create_chat_completion_openai_v1
            response_wrapper = lambda r: iter([r])  # sadly we can't stream with auto tool choice: https://github.com/abetlen/llama-cpp-python/discussions/1615
            extra_args = {}
        else:
            completion = litellm_completion
            extra_args = {"num_retries": 3,
                          "base_url": model.uri,
                          "stream": True}
            response_wrapper = lambda r: r
        response = completion(
            model=f"{model.platform}/{model.id}",
            max_tokens=int(interpreter.env["llm.maxtokens"]),
            tools=get_ai_tools(),
            messages=interpreter.messages,
            tool_choice="auto",
            temperature=float(interpreter.env["llm.temperature"]),
            **extra_args
            )
        call = process_streaming_response(
            interpreter, response_wrapper(response))
    return response