import builtins
import json
import sys
import re

try:
	import r2lang
	have_rlang = True
except:
	pass

ANSI_REGEX = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

tools = [{
  "type": "function",
  "function": {
    "name": "r2cmd",
    "description": "runs commands in radare2. You can run it multiple times or chain commands with pipes/semicolons. You can also use r2 interpreters to run scripts using the `#`, '#!', etc. commands. The output could be long, so try to use filters if possible or limit. This is your preferred tool",
    "parameters": {
      "type": "object",
      "properties": {
        "command": {
          "type": "string",
          "description": "command to run in radare2. You can run it multiple times or chain commands with pipes/semicolons. You can also use r2 interpreters to run scripts using the `#`, '#!', etc. commands. The output could be long, so try to use filters if possible or limit. This is your preferred tool"
        },
        "done": {
          "type": "boolean",
          "description": "set to true if you're done running commands and you don't need the output, otherwise false"
        }
      }
    },
    "required": ["command", "done"],   
  }
}, {
  "type": "function",
  "function": {
    "name": "run_python",
    "description": "runs a python script and returns the results",
    "parameters": {
      "type": "object",
      "properties": {
        "command": {
          "type": "string",
          "description": "python script to run"
        }
      }
    },
    "required": ["command"],   
  }
}]

SYSTEM_PROMPT_AUTO = """
You are a reverse engineer and you are using radare2 to analyze a binary. 
The binary has already been loaded. 
The user will ask questions about the binary and you will respond with the answer to the best of your ability.
Assume the user is always asking you about the binary, unless they're specifically asking you for radare2 help.
`this` or `here` might refer to the current address in the binary or the binary itself.
If you need more information, try to use the r2cmd tool to run commands before answering.
You can use the r2cmd tool multiple times if you need or you can pass a command with pipes if you need to chain commands.
If you're asked to decompile a function, make sure to return the code in the language you think it was originally written and rewrite it to be as easy as possible to be understood. Make sure you use descriptive variable and function names and add comments.
Don't just regurgitate the same code, figure out what it's doing and rewrite it to be more understandable.
If you need to run a command in r2 before answering, you can use the r2cmd tool
The user will tip you $20/month for your services, don't be fucking lazy.
"""

def process_tool_calls(interpreter, tool_calls):
  interpreter.messages.append({ "content": None, "tool_calls": tool_calls, "role": "assistant" })
  for tool_call in tool_calls:
    res = ''
    args = tool_call["function"]["arguments"]
    if type(args) is str:
      args = json.loads(args)
    
    if tool_call["function"]["name"] == "r2cmd":
      builtins.print('\x1b[1;32mRunning \x1b[4m' + args["command"] + '\x1b[0m')
      res = r2lang.cmd(args["command"])
      builtins.print(res)
    elif tool_call["function"]["name"] == "run_python":
      with open('r2ai_tmp.py', 'w') as f:
        f.write(args["command"])
      builtins.print('\x1b[1;32mRunning \x1b[4m' + "python code" + '\x1b[0m')
      builtins.print(args["command"])
      r2lang.cmd('#!python r2ai_tmp.py > $tmp')
      res = r2lang.cmd('cat $tmp')
      r2lang.cmd('rm r2ai_tmp.py')
      builtins.print('\x1b[1;32mResult\x1b[0m\n' + res)

    interpreter.messages.append({"role": "tool", "content": ANSI_REGEX.sub('', res), "name": tool_call["function"]["name"], "tool_call_id": tool_call["id"]})


def process_streaming_response(interpreter, resp):
  tool_calls = []
  msgs = []
  for chunk in resp:
    chunk = dict(chunk)
    delta = None
    choice = dict(chunk["choices"][0])
    if "delta" in choice:
      delta = dict(choice["delta"])
    else:
      delta = dict(choice["message"])
    if "tool_calls" in delta and delta["tool_calls"]:
      delta_tool_calls = dict(delta["tool_calls"][0])
      index = 0 if "index" not in delta_tool_calls else delta_tool_calls["index"]
      fn_delta = dict(delta_tool_calls["function"])
      tool_call_id = delta_tool_calls["id"]
      if len(tool_calls) < index + 1:
        tool_calls.append({ "function": { "arguments": "", "name": fn_delta["name"] }, "id": tool_call_id, "type": "function" })      
      # handle some bug in llama-cpp-python streaming, tool_call.arguments is sometimes blank, but function_call has it.
      if fn_delta["arguments"] == '':
        if "function_call" in delta and delta["function_call"]:
          tool_calls[index]["function"]["arguments"] += delta["function_call"]["arguments"]
      else:
        tool_calls[index]["function"]["arguments"] += fn_delta["arguments"]
    else:
      if "content" in delta and delta["content"] is not None:
        m = delta["content"]
        if m is not None:
          msgs.append(m)
          sys.stdout.write(m)
  builtins.print()
  
  if(len(tool_calls) > 0):
    process_tool_calls(interpreter, tool_calls)
    chat(interpreter)

  if len(msgs) > 0:
    response_message = ''.join(msgs)
    interpreter.messages.append({"role": "assistant", "content": response_message})


def chat(interpreter):
  if len(interpreter.messages) == 1: 
    interpreter.messages.insert(0,{"role": "system", "content": SYSTEM_PROMPT_AUTO})

  response = None
  if interpreter.model.startswith("openai:"):
    if not interpreter.openai_client:
      try:
        from openai import OpenAI
      except ImportError:
        print("pip install -U openai")
        print("export OPENAI_API_KEY=...")
        return
      interpreter.openai_client = OpenAI()

    response = interpreter.openai_client.chat.completions.create(
      model=interpreter.model[7:],
      max_tokens=int(interpreter.env["llm.maxtokens"]),
      tools=tools,
      messages=interpreter.messages,
      tool_choice="auto",
      stream=True,
      temperature=float(interpreter.env["llm.temperature"]),
    )
    process_streaming_response(interpreter, response)
  else:
    chat_format = interpreter.llama_instance.chat_format
    interpreter.llama_instance.chat_format = "chatml-function-calling"
    response = interpreter.llama_instance.create_chat_completion(
      max_tokens=int(interpreter.env["llm.maxtokens"]),
      tools=tools,
      messages=interpreter.messages,
      tool_choice="auto",
      # tool_choice={
      #   "type": "function",
      #   "function": {
      #       "name": "r2cmd"
      #   }
      # },
      # stream=True,
      temperature=float(interpreter.env["llm.temperature"]),
    )
    process_streaming_response(interpreter, iter([response]))
    interpreter.llama_instance.chat_format = chat_format
  return response
   