from litellm import acompletion, ChatCompletionAssistantToolCall, ChatCompletionToolCallFunctionChunk
import asyncio
import json
import signal
from r2ai.pipe import get_r2_inst
from r2ai.tools import run_python, r2cmd
from r2ai.repl import r2ai_singleton
from r2ai.auto import ChatAuto, SYSTEM_PROMPT_AUTO
from r2ai.interpreter import is_litellm_model
from r2ai.models import new_get_hf_llm

def signal_handler(signum, frame):
    raise KeyboardInterrupt

async def chat(ai, message, cb):
    model = ai.model.replace(":", "/")
    tools = [r2cmd, run_python]
    messages = ai.messages + [{"role": "user", "content": message}]
    tool_choice = 'auto'
    if not is_litellm_model(model) and ai and not ai.llama_instance:
        ai.llama_instance = new_get_hf_llm(ai, model, int(ai.env["llm.window"]))
    
    chat_auto = ChatAuto(model, interpreter=ai, system=SYSTEM_PROMPT_AUTO, tools=tools, messages=messages, tool_choice=tool_choice, cb=cb)
    
    original_handler = signal.getsignal(signal.SIGINT)

    try:
        signal.signal(signal.SIGINT, signal_handler)
        return await chat_auto.achat(stream=True)
    except KeyboardInterrupt:
        tasks = asyncio.all_tasks()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        return None
    finally:
        signal.signal(signal.SIGINT, original_handler)