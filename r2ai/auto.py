import builtins
import json
import sys
import re
from . import LOGGER
import litellm
from litellm import _should_retry, acompletion, utils, ModelResponse
import asyncio
from .pipe import get_filename
from .tools import r2cmd, run_python, execute_binary
import json
import signal
from .spinner import spinner
from .completion import create_chat_completion
import uuid

litellm.drop_params = True

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
    def __init__(self, model, max_tokens = 1024, top_p=0.95, temperature=0.0, interpreter=None, system=None, tools=None, messages=None, tool_choice='auto', llama_instance=None, timeout=None, stream=True, cb=None ):
        self.logger = LOGGER
        self.functions = {}
        self.tools = []
        self.model = model
        self.max_tokens = max_tokens
        self.top_p = top_p
        self.temperature = temperature
        self.system = system
        self.messages = messages
        self.interpreter = interpreter
        self.system_message = None
        self.timeout = timeout
        self.stream = stream
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
        self.llama_instance = llama_instance or interpreter.llama_instance if interpreter else None
        #self.tool_end_message = '\nNOTE: The user saw this output, do not repeat it.'

    async def process_tool_calls(self, tool_calls):
        if tool_calls:
            for tool_call in tool_calls:
                self.logger.debug(f"tool_call: {tool_call}")
                tool_name = tool_call["function"]["name"]
                if "id" not in tool_call:
                    tool_call["id"] = str(uuid.uuid4())
                try:
                    tool_args = json.loads(tool_call["function"]["arguments"])
                except Exception:
                    if "arguments" in tool_call["function"] and type(tool_call["function"]["arguments"]) == dict:
                        tool_args = tool_call["function"]["arguments"]
                    else:
                        self.logger.error(f'Error parsing JSON: {tool_call["function"]["arguments"]}')
                        # raise Exception('Error parsing JSON')
                        self.messages.append({"role": "tool", "name": tool_name, "content": "Error: Unable to parse JSON" , "tool_call_id": tool_call["id"]})
                        continue
                if tool_name not in self.functions:
                    self.logger.error(f'Tool not found: {tool_name}')
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
        parts = []
        current_message = { "role": "assistant", "content": "", "tool_calls": [] }
        async for chunk in resp:
            delta = None
            choice = chunk.choices[0]
            delta = choice.delta
            if delta.tool_calls:
                delta_tool_calls = delta.tool_calls[0]
                index = delta_tool_calls.index
                fn_delta = delta_tool_calls.function
                tool_call_id = delta_tool_calls.id
                if len(current_message['tool_calls']) < index + 1:
                    tool_call = {
                            "id": tool_call_id or str(uuid.uuid4()),
                            "type": "function",
                            "function": {
                                "name":fn_delta.name,
                                "arguments": fn_delta.arguments
                            }
                        }
                    current_message['tool_calls'].append(tool_call)
                else:
                    if fn_delta.name:
                        current_message['tool_calls'][index]["function"]["name"] = fn_delta.name
                    current_message['tool_calls'][index]["function"]["arguments"] += fn_delta.arguments
            else:
                m = None
                done = False
                if delta.content is not None:
                    m = delta.content
                    if m is not None:
                        current_message['content'] += m
                    self.cb('message', { "content": m, "id": 'message_' + chunk.id, 'done': False })
                if 'finish_reason' in choice and choice['finish_reason'] == 'stop':
                    done = True
                    self.cb('message', { "content": "", "id": 'message_' + chunk.id, 'done': True })
                self.cb('message_stream', { "content": m if m else '', "id": 'message_' + chunk.id, 'done': done })
        self.messages.append(current_message)
        if len(current_message['tool_calls']) > 0:
            await self.process_tool_calls(current_message['tool_calls'])
        return current_message

    async def process_response(self, resp):
        content = resp.choices[0].message.content
        tool_calls = []
        current_message = { 'role': 'assistant', 'content': content or '', 'tool_calls': [] }
        for tool_call in resp.choices[0].message.tool_calls or []:
            current_message['tool_calls'].append({
                "id": tool_call.id,
                "type": "function",
                "index": tool_call.index,
                "function": {
                    "name": tool_call.function.name,
                    "arguments": tool_call.function.arguments
                },
            })
        if len(current_message['tool_calls']) == 0:
            try:
                tool_call = json.loads(content)
                if 'name' in tool_call and tool_call['name'] in self.functions:
                    args = None
                    if 'arguments' in tool_call:
                        args = tool_call['arguments']
                    elif 'parameters' in tool_call:
                        args = tool_call['parameters']
                    if args:
                        current_message['tool_calls'].append({ "id": resp.id, "function": { "name": tool_call['name'], "arguments": json.dumps(args) } })
            except Exception:
                pass
        if len(current_message['tool_calls']) > 0:
            self.messages.append(current_message)
            await self.process_tool_calls(current_message['tool_calls'])
        
        self.messages.append(current_message)

        return current_message
        
    async def async_response_generator(self, response):
        for item in response:
            resp = ModelResponse(stream=True, **item)
            yield resp

    async def attempt_completion(self):
        stream = self.stream
        if self.llama_instance:        
            args = {
                "temperature": self.temperature,
                "top_p": self.top_p,
                "max_tokens": self.max_tokens,
                "stream": stream,
            }
            res = create_chat_completion(self.interpreter, messages=self.messages, tools=[self.tools[0]], **args)
            if args['stream']:
                return self.async_response_generator(res)
            else:
                return ModelResponse(**next(res))
        self.logger.debug('chat completion')
        return await acompletion(
            model=self.model,
            messages=self.messages,
            timeout=self.timeout,
            tools=self.tools,
            tool_choice=self.tool_choice,
            temperature=self.temperature,
            top_p=self.top_p,
            max_tokens=self.max_tokens,
            stream=stream,
        )

    async def get_completion(self):
        stream = self.stream
        if self.llama_instance:
            response = await self.attempt_completion()
            if stream:
                return await self.process_streaming_response(response)
            else:
                return await self.process_response(response)
        max_retries = 5
        base_delay = 2
        
        for retry_count in range(max_retries):
            try:
                response = await self.attempt_completion()
                self.logger.debug(f'chat completion {response}')
                if stream:
                    return await self.process_streaming_response(response)
                else:
                    return await self.process_response(response)                
            except Exception as e:
                self.logger.error(f'Error getting completion: {e}')
                if not _should_retry(getattr(e, 'status_code', None)) or retry_count == max_retries - 1:
                    raise
                
                delay = base_delay * (2 ** retry_count)
                self.logger.info(f"Retrying in {delay} seconds...")
                await asyncio.sleep(delay)
        
        raise Exception("Max retries reached. Unable to get completion.")

    async def achat(self, messages=None) -> str:
        if messages:
            self.messages = messages
        response = await self.get_completion()
        self.logger.debug(f'chat complete')
        return response
    
    def chat(self, **kwargs) -> str:
        return asyncio.run(self.achat(**kwargs))

def cb(type, data):
    spinner.stop()
    if type == 'message_stream':
        if 'content' in data:
            sys.stdout.write(data['content'])
    elif type == 'tool_call':
        builtins.print()
        if data['function']['name'] == 'r2cmd':
            builtins.print('\x1b[1;32m> \x1b[4m' + data['function']['arguments']['command'] + '\x1b[0m')
        elif data['function']['name'] == 'run_python':
            builtins.print('\x1b[1;32m> \x1b[4m' + "#!python" + '\x1b[0m')
            builtins.print(data['function']['arguments']['command'])
        elif data['function']['name'] == 'execute_binary':
            filename = get_filename()
            stdin = data['function']['arguments']['stdin']
            args = data['function']['arguments']['args']
            cmd = filename
            if len(args) > 0:
                cmd += ' ' + ' '.join(args)
            if stdin:
                cmd += f' stdin={stdin}'
            builtins.print('\x1b[1;32m> \x1b[4m' + cmd + '\x1b[0m')
    elif type == 'tool_response':
        if 'content' in data:
            sys.stdout.write(data['content'])
            sys.stdout.flush()
        # builtins.print(data['content'])
    elif type == 'message' and data['done']:
        builtins.print()

def signal_handler(signum, frame):
    raise KeyboardInterrupt

def chat(interpreter, **kwargs):
    model = interpreter.model.replace(":", "/")
    tools = [r2cmd, run_python, execute_binary]
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

    chat_auto = ChatAuto(model, max_tokens=int(interpreter.env["llm.maxtokens"]), top_p=float(interpreter.env["llm.top_p"]), temperature=float(interpreter.env["llm.temperature"]), interpreter=interpreter, system=SYSTEM_PROMPT_AUTO, tools=tools, messages=messages, tool_choice=tool_choice, llama_instance=interpreter.llama_instance, cb=cb)
    
    original_handler = signal.getsignal(signal.SIGINT)

    try:
        signal.signal(signal.SIGINT, signal_handler)
        spinner.start()
        return loop.run_until_complete(chat_auto.achat())
    except KeyboardInterrupt:
        builtins.print("\033[91m\nOperation cancelled by user.\033[0m")
        tasks = asyncio.all_tasks(loop=loop)
        for task in tasks:
            task.cancel()
        try:
            loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
            loop.run_until_complete(asyncio.sleep(0.1))
        except asyncio.CancelledError:
            pass
        return None
    finally:
        signal.signal(signal.SIGINT, original_handler)
        spinner.stop()
        try:
            pending = asyncio.all_tasks(loop=loop)
            for task in pending:
                task.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()