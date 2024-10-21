from litellm import acompletion, ChatCompletionAssistantToolCall, ChatCompletionToolCallFunctionChunk
import asyncio
import json
import signal
from r2ai.pipe import get_r2_inst
from r2ai.tools import run_python, r2cmd
from r2ai.repl import r2ai_singleton
from r2ai.auto import ChatAuto, SYSTEM_PROMPT_AUTO

def signal_handler(signum, frame):
    raise KeyboardInterrupt

async def chat(ai, message, cb):
    model = ai.model.replace(":", "/")
    tools = [r2cmd, run_python]
    messages = ai.messages + [{"role": "user", "content": message}]
    tool_choice = 'auto'

    chat_auto = ChatAuto(model, system=SYSTEM_PROMPT_AUTO, tools=tools, messages=messages, tool_choice=tool_choice, cb=cb)
    
    original_handler = signal.getsignal(signal.SIGINT)

    try:
        signal.signal(signal.SIGINT, signal_handler)
        return await chat_auto.chat()
    except KeyboardInterrupt:
        tasks = asyncio.all_tasks()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        return None
    finally:
        signal.signal(signal.SIGINT, original_handler)