import builtins
import json
import sys
import re
import os
from llama_cpp import Llama
from llama_cpp.llama_tokenizer import LlamaHFTokenizer
from transformers import AutoTokenizer
from . import index
from .pipe import have_rlang, r2lang, get_r2_inst
from litellm import _should_retry, acompletion, utils, ModelResponse
import asyncio
from r2ai.pipe import get_r2_inst
from .tools import r2cmd, run_python
import json
import signal
from .spinner import spinner

ANSI_REGEX = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

SYSTEM_PROMPT_AUTO = """
You are a reverse engineer and you are using radare2 to analyze a binary.
The user will ask questions about the binary and you will respond with the answer to the best of your ability.

# Guidelines
- Understand the Task: Grasp the main objective, goals, requirements, constraints, and expected output.
- Reasoning Before Conclusions**: Encourage reasoning steps before any conclusions are reached.
- Assume the user is always asking you about the binary, unless they're specifically asking you for radare2 help.
- The binary has already been loaded. You can interact with the binary using the r2cmd tool.
- `this` or `here` might refer to the current address in the binary or the binary itself.
- If you need more information, try to use the r2cmd tool to run commands before answering.
- You can use the r2cmd tool multiple times if you need or you can pass a command with pipes if you need to chain commands.
- If you're asked to decompile a function, make sure to return the code in the language you think it was originally written and rewrite it to be as easy as possible to be understood. Make sure you use descriptive variable and function names and add comments.
- Don't just regurgitate the same code, figure out what it's doing and rewrite it to be more understandable.
- If you need to run a command in r2 before answering, you can use the r2cmd tool
- Do not repeat commands if you already know the answer.
- Formulate a plan. Think step by step. Analyze the binary as much as possible before answering.
- You must keep going until you have a final answer.
- Double check that final answer. Make sure you didn't miss anything.
- Make sure you call tools and functions correctly.
"""

class ChatAuto:
    def __init__(self, model, system=None, tools=None, messages=None, tool_choice='auto', llama_instance=None, cb=None ):
        self.functions = {}
        self.tools = []
        self.model = model
        self.system = system
        self.messages = messages
        if messages and messages[0]['role'] != 'system' and system:
            self.messages.insert(0, { "role": "system", "content": system })
        if cb:
            self.cb = cb
        else:
            self.cb = lambda *args: None
        self.tool_choice = None
        if tools:
            for tool in tools:
                f = utils.function_to_dict(tool)
                self.tools.append({ "type": "function", "function": f })
                self.functions[f['name']] = tool
            self.tool_choice = tool_choice
        self.llama_instance = llama_instance
        
        #self.tool_end_message = '\nNOTE: The user saw this output, do not repeat it.'

    async def process_tool_calls(self, tool_calls):
        if tool_calls:
            for tool_call in tool_calls:
                tool_name = tool_call["function"]["name"]
                try:
                    tool_args = json.loads(tool_call["function"]["arguments"])
                except Exception:
                    self.messages.append({"role": "tool", "name": tool_name, "content": "Error: Unable to parse JSON" , "tool_call_id": tool_call["id"]})
                    continue
                if tool_name not in self.functions:
                    self.messages.append({"role": "tool", "name": tool_name, "content": "Error: Tool not found" , "tool_call_id": tool_call["id"]})
                    continue
              
                self.cb('tool_call', { "id": tool_call["id"], "function": { "name": tool_name, "arguments": tool_args } })
                if asyncio.iscoroutinefunction(self.functions[tool_name]):
                    tool_response = await self.functions[tool_name](**tool_args)
                else:
                    tool_response = self.functions[tool_name](**tool_args)
                self.cb('tool_response', { "id": tool_call["id"] + '_response', "content": tool_response })
                self.messages.append({"role": "tool", "name": tool_name, "content": ANSI_REGEX.sub('', tool_response), "tool_call_id": tool_call["id"]})
                
        return await self.get_completion()

    async def process_streaming_response(self, resp):
        tool_calls = []
        msgs = []
        async for chunk in resp:
            delta = None
            choice = chunk.choices[0]
            delta = choice.delta
            if delta.tool_calls:
                delta_tool_calls = delta.tool_calls[0]
                index = delta_tool_calls.index
                fn_delta = delta_tool_calls.function
                tool_call_id = delta_tool_calls.id
                if len(tool_calls) < index + 1:
                    tool_calls.append({
                            "id": tool_call_id,
                            "type": "function",
                            "function": {
                                "name":fn_delta.name,
                                "arguments": fn_delta.arguments
                            }
                        }
                    )
                else:
                    tool_calls[index]["function"]["arguments"] += fn_delta.arguments
            else:
                m = None
                done = False
                if delta.content is not None:
                    m = delta.content
                    if m is not None:
                        msgs.append(m)
                    self.cb('message', { "content": m, "id": 'message_' + chunk.id, 'done': False })
                if 'finish_reason' in choice and choice['finish_reason'] == 'stop':
                    done = True
                    self.cb('message', { "content": "", "id": 'message_' + chunk.id, 'done': True })
                self.cb('message_stream', { "content": m if m else '', "id": 'message_' + chunk.id, 'done': done })
        if (len(tool_calls) > 0):
            self.messages.append({"role": "assistant", "tool_calls": tool_calls})
            await self.process_tool_calls(tool_calls)
        if len(msgs) > 0:
            response_message = ''.join(msgs)
            self.messages.append({"role": "assistant", "content": response_message})
            return response_message

    async def attempt_completion(self):
        args = {
            "temperature": 0,
            "tools": self.tools,
            "tool_choice": self.tool_choice,
            "stream": True
        }
        if self.llama_instance:
            return self.llama_instance.create_chat_completion(self.messages, **args)

        return await acompletion(
            model=self.model,
            messages=self.messages,
            **args
        )

    async def get_completion(self):
        if self.llama_instance:
            response = await self.attempt_completion()
            async def async_generator(response):
                for item in response:
                    yield ModelResponse(stream=True, **item)
            return await self.process_streaming_response(async_generator(response))
        max_retries = 5
        base_delay = 2
        
        for retry_count in range(max_retries):
            try:
                response = await self.attempt_completion()
                return await self.process_streaming_response(response)
            except Exception as e:
                print(e)
                if not _should_retry(getattr(e, 'status_code', None)) or retry_count == max_retries - 1:
                    raise
                
                delay = base_delay * (2 ** retry_count)
                print(f"Retrying in {delay} seconds...")
                await asyncio.sleep(delay)
        
        raise Exception("Max retries reached. Unable to get completion.")

    async def chat(self) -> str:
        response = await self.get_completion()
        return response
    
def cb(type, data):
    spinner.stop()
    if type == 'message_stream':
        sys.stdout.write(data['content'])
    elif type == 'tool_call':
        if data['function']['name'] == 'r2cmd':
            builtins.print('\x1b[1;32m> \x1b[4m' + data['function']['arguments']['command'] + '\x1b[0m')
        elif data['function']['name'] == 'run_python':
            builtins.print('\x1b[1;32m> \x1b[4m' + "#!python" + '\x1b[0m')
            builtins.print(data['function']['arguments']['command'])
    elif type == 'tool_response':
        sys.stdout.write(data['content'])
        sys.stdout.flush()
        # builtins.print(data['content'])
    elif type == 'message' and data['done']:
        builtins.print()

def signal_handler(signum, frame):
    raise KeyboardInterrupt

def chat(interpreter, llama_instance=None):
    model = interpreter.model.replace(":", "/")
    tools = [r2cmd, run_python]
    messages = interpreter.messages
    tool_choice = 'auto'

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed() or loop.is_running():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    chat_auto = ChatAuto(model, system=SYSTEM_PROMPT_AUTO, tools=tools, messages=messages, tool_choice=tool_choice, llama_instance=llama_instance, cb=cb)
    
    original_handler = signal.getsignal(signal.SIGINT)

    try:
        signal.signal(signal.SIGINT, signal_handler)
        spinner.start()
        return loop.run_until_complete(chat_auto.chat())
    except KeyboardInterrupt:
        builtins.print("\033[91m\nOperation cancelled by user.\033[0m")
        tasks = asyncio.all_tasks(loop=loop)
        for task in tasks:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        return None
    finally:
        signal.signal(signal.SIGINT, original_handler)
        spinner.stop()
        loop.stop()
        loop.close()