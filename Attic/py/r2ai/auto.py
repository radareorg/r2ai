import builtins
import json
import sys
import re
from . import LOGGER
import litellm
from litellm import _should_retry, acompletion, utils, ModelResponse
import asyncio
from .pipe import get_filename
from .tools import r2cmd, run_python, execute_binary, schemas, print_tool_call
import json
import signal
from .spinner import spinner
from .completion import create_chat_completion
import uuid
import time
import readline
import subprocess
import shlex
import os
import tempfile

# litellm.drop_params = True
# litellm.set_verbose=True

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

SYSTEM_PROMPT_AUTO_REASONING = f"""
You are an expert reverse engineer.
The user will ask questions about the binary and you will respond with the answer to the best of your ability.
You can use the available tools to help you answer the user's question.
The binary has already been loaded. You can interact with the binary using the r2cmd tool.
If you need to run a command in r2 before answering, you can use the r2cmd tool
"""

class ChatAuto:
    def __init__(self, model, max_tokens = 32000, top_p=0.95, temperature=0.0, interpreter=None, system=None, tools=None, ask_to_execute=True, messages=None, tool_choice='auto', llama_instance=None, timeout=60, stream=True, cb=None, max_runs=100):
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
        self.cost = 0
        self.is_reasoning = False
        self.n_runs = 0
        self.max_runs = max_runs
        self._last_response = None
        self._start_time = time.time()
        self._last_run_time = time.time()
        self.ask_to_execute = ask_to_execute
        self.llama_instance = llama_instance or interpreter.llama_instance if interpreter else None
        
        init_prompt = ""
        
        if not self.llama_instance:
            rmodel = re.sub(r'ft:([^:]+).*', r'\1', self.model)
            model_info = litellm.get_model_info(rmodel)
            self.max_tokens = min(self.max_tokens, model_info['max_tokens'])

            if self.model.startswith('openai/o'):
                self.is_reasoning = True
                self.max_tokens = model_info['max_tokens']
                self.timeout = 60 * 60
            init_commands = self.interpreter.env["auto.init_commands"]
            
            if init_commands:
                init_prompt = f"""
Here is some information about the binary to get you started:
> {init_commands}
{r2cmd(init_commands)}
"""
        if self.is_reasoning:
            if not system and not self.messages[0]['role'] == 'developer':
                self.messages.insert(0, { "role": "developer", "content": SYSTEM_PROMPT_AUTO_REASONING + init_prompt })
            self.stream = False
        else:
            if messages and messages[0]['role'] != 'system':
                self.messages.insert(0, { "role": "system", "content": system or SYSTEM_PROMPT_AUTO + init_prompt })


        if cb:
            self.cb = cb
        else:
            self.cb = lambda *args: None
        self.tool_choice = None
        if tools:
            for tool in tools:
                if tool.__name__ in schemas:
                    schema = schemas[tool.__name__]
                else:
                    schema = utils.function_to_dict(tool)
                
                self.tools.append({ "type": "function", "function": schema })
                self.functions[tool.__name__] = tool
            self.tool_choice = tool_choice
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

                if self.ask_to_execute:
                    # tool_call typically contains:
                    # { 'id': 'toolu_01Hr6XTatRtp7rX54iBu1voC', 'type': 'function', 'function': {'name': 'r2cmd', 'arguments': '{"command": "pdf @ main"}'}}
                    answer = ''
                    will_execute = True # a command (modified or not) will be executed
                    while answer.lower() != 'y':
                        try:
                            command = tool_args.get('command', '')

                            if len(command.splitlines()) > 1:
                                print(f'r2ai is going to execute the following command on the host:')
                                print(f'{command}')
                                want_edit = input('Want to edit? (Y/n) ')
                                if want_edit.lower() != 'n':
                                    # open editor when several lines
                                    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                                        temp_file.write(command) 
                                        temp_filename = temp_file.name 

                                    # Fallback to 'nano' if EDITOR is not set (I still prefer emacs)
                                    editor = os.environ.get('EDITOR', 'nano')  
                                    subprocess.run(shlex.split(editor + ' ' + temp_filename))
                                    with open(temp_filename, "r") as f:
                                        new_command = f.read().strip()
                                    os.remove(temp_filename)
                                else:
                                    self.logger.debug(f'User agrees with not editing the command: {command}')
                                    answer = 'y'

                            else:
                                # inline short edit
                                print(f'r2ai is going to execute the following command on the host:')
                                print(f'> {command}')
                                
                                new_command = input(f"Type a new command or press ENTER to use {command} ") or command

                            if answer.lower() != 'y':
                                answer = input(f"\033[91mThis command will execute on this host: {new_command}. Agree? (y/N)\033[0m ")
                                if answer.lower() == 'y':
                                    # we need to refresh tool_call and tool_args with edited values
                                    tool_args['command'] = new_command
                                    tool_call['function']['arguments'] = json.dumps(tool_args)

                        except (json.JSONDecodeError, TypeError, AttributeError) as e:
                            # in case tool_call is not formatted as expected, like missing command, arguments, function...
                            self.logger.error(f'Unexpected format for {tool_call}')
                            self.messages.append({"role": "tool", "name": tool_name, "content": "User refused to execute the command" , "tool_call_id": tool_call["id"]})
                            # error case: we'll skip the tool
                            will_execute = False
                            break

                    if not will_execute:
                        self.logger.debug(f'Skipping tool={tool_call}')
                        continue

                self.logger.debug(f'Executing tool id={tool_call["id"]}, name={tool_name}, arguments={tool_args}')
                self.cb('tool_call', { "id": tool_call["id"], "function": { "name": tool_name, "arguments": tool_args } })
                if asyncio.iscoroutinefunction(self.functions[tool_name]):
                    tool_response = await self.functions[tool_name](**tool_args)
                else:
                    tool_response = self.functions[tool_name](**tool_args)
                if self.interpreter.env["auto.hide_tool_output"] == "false":
                    self.cb('tool_response', { "id": tool_call["id"] + '_response', "content": tool_response })
                self.messages.append({"role": "tool", "name": tool_name, "content": ANSI_REGEX.sub('', tool_response), "tool_call_id": tool_call["id"]})

        return await self.get_completion()

    async def process_streaming_response(self, resp):
        tool_calls = []
        msgs = []
        parts = []
        current_message = { "role": "assistant", "content": "", "tool_calls": [] }
        first_chunk = True
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
                    if first_chunk:
                        self.cb('message', { 'content': "\n\x1b[1;32massistant\x1b[0m\n", 'done': True })
                        first_chunk = False
                    m = delta.content
                    if m is not None:
                        current_message['content'] += m
                    self.cb('message', { "content": m, "id": 'message_' + chunk.id, 'done': False })
                if 'finish_reason' in choice and choice['finish_reason'] == 'stop':
                    done = True
                    self.cb('message', { "content": "", "id": 'message_' + chunk.id, 'done': True })
                self.cb('message_stream', { "content": m if m else '', "id": 'message_' + chunk.id, 'done': done })
        self.messages.append(current_message)
        if len(current_message['tool_calls']) == 0:
            del current_message['tool_calls']
            self.show_cost()
        else:
            self.show_cost()
            await self.process_tool_calls(current_message['tool_calls'])
                    
        return current_message

    async def process_response(self, resp):
        content = resp.choices[0].message.content
        
        current_message = { 'role': 'assistant', 'content': content or '', 'tool_calls': [] }
        for i, tool_call in enumerate(resp.choices[0].message.tool_calls or []):
            current_message['tool_calls'].append({
                "id": tool_call.id,
                "type": "function",
                "index": i,
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
        self.messages.append(current_message)
        if current_message['content'] != "":
            self.cb('message', { 'content': "\n\x1b[1;32massistant\x1b[0m\n", 'done': True })
            self.cb('message', { "content": current_message['content'], "id": 'message_' + resp.id, 'done': True })

        if len(current_message['tool_calls']) == 0:
            del current_message['tool_calls']
            self.show_cost()
        else:
            self.show_cost()
            await self.process_tool_calls(current_message['tool_calls'])

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
            if self.interpreter.env["chat.rawdog"] == "true":
                res = create_chat_completion(self.interpreter, messages=self.messages, tools=self.tools, **args)
            else:
                res = self.llama_instance.create_chat_completion(self.messages, tools=self.tools, **args)
            if args['stream']:
                return self.async_response_generator(res)
            else:
                return ModelResponse(**next(res))
        additional_args = {}
        if self.is_reasoning:
            additional_args['reasoning_effort'] = self.interpreter.env["chat.reasoning_effort"]
        else:
            additional_args['temperature'] = self.temperature
        if self.interpreter.env["chat.openai_store"] == "true":
            additional_args['store'] = True
        if not self.check_max():
            additional_args['tools'] = self.tools
            additional_args['tool_choice'] = self.tool_choice
        compl = await acompletion(
            model=self.model,
            messages=self.messages,
            timeout=self.timeout,
            max_completion_tokens=self.max_tokens,
            **additional_args,
            stream=stream,
        )
        return compl

    def check_max(self):
        if self.max_runs > 0 and self.n_runs >= self.max_runs - 1:
            return True
        return False
    
    def show_cost(self):
        def format_time(seconds):
            minutes = int(seconds // 60)
            remaining_seconds = int(seconds % 60)
            if minutes > 0:
                return f"{minutes}m {remaining_seconds}s"
            return f"{remaining_seconds}s"
        self.n_runs += 1
        run_time = format_time(time.time() - self._last_run_time)
        self._last_run_time = time.time()
        total_time = format_time(time.time() - self._start_time)
        
        if self.interpreter.env["chat.show_cost"] == "true" and self.n_runs > 0:
            run_cost = 0
            if not self.llama_instance:
                run_cost = litellm.completion_cost(completion_response=self._last_response, messages=self.messages, model=self.model)
                self.cost += run_cost
            cb('usage', { 
                "model": self.model, 
                "run_cost": run_cost, 
                "total_cost": self.cost, 
                "n_runs": self.n_runs, 
                "max_runs": self.max_runs,
                "run_time": run_time,
                "total_time": total_time
            })

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
                self._last_response = response
                self.logger.debug(f'chat completion {response}')
                res = None
                if stream:
                    res = await self.process_streaming_response(response)
                else:
                    res = await self.process_response(response)

                return res
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
        self.logger.debug(self.messages)
        response = await self.get_completion()
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
        print_tool_call(data)
    elif type == 'tool_response':
        if 'content' in data:
            sys.stdout.write(data['content'])
            sys.stdout.flush()
            builtins.print()
    elif type == 'usage':
        sys.stdout.flush()
        builtins.print()
        sys.stdout.write(f'\x1b[1;34m{data["model"]} | total: ${float(data["total_cost"]):.10f} | run: ${float(data["run_cost"]):.10f} | {data["n_runs"]} / {data["max_runs"]} | {data["run_time"]} / {data["total_time"]}\x1b[0m')
        sys.stdout.flush()
        builtins.print()
    elif type == 'message' and data['done']:
        if data['content']:
            sys.stdout.flush()
            sys.stdout.write(data['content'])
            sys.stdout.flush()
        else:
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

    chat_auto = ChatAuto(
        model, 
        max_tokens=int(interpreter.env["llm.maxtokens"]), 
        top_p=float(interpreter.env["llm.top_p"]), 
        temperature=float(interpreter.env["llm.temperature"]), 
        interpreter=interpreter, 
        tools=tools, 
        ask_to_execute=interpreter.env["auto.ask_to_execute"] == "true",
        messages=messages, 
        tool_choice=tool_choice, 
        llama_instance=interpreter.llama_instance, 
        stream=interpreter.env["chat.stream"] == "true",
        max_runs=int(interpreter.env["auto.max_runs"]),
        cb=cb
    )
    
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
        litellm.in_memory_llm_clients_cache.flush_cache()
