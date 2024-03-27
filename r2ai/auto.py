import builtins
import json
import sys
import re
from llama_cpp import Llama
from llama_cpp.llama_tokenizer import LlamaHFTokenizer
from transformers import AutoTokenizer
from .functionary import prompt_template
from .anthropic import construct_tool_use_system_prompt, extract_claude_tool_calls

try:
	import r2lang
	have_rlang = True
except:
  import r2pipe
  class FakeLang:
    def __init__(self):
      self.r2 = r2pipe.open()
    def cmd(self,x):
      return self.r2.cmd(x)
  r2lang = FakeLang()
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
          "description": "command to run in radare2"
        }
      }
    },
    "required": ["command"],   
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
Do not repeat commands if you already know the answer.
"""

FUNCTIONARY_PROMPT_AUTO = """
  Think step by step.
  Break down the task into steps and execute the necessary `radare2` commands in order to complete the task.
"""

def get_system_prompt(model):
  if model.startswith("meetkai/"):
    return SYSTEM_PROMPT_AUTO + "\n" + FUNCTIONARY_PROMPT_AUTO
  elif model.startswith("anthropic"):
    return SYSTEM_PROMPT_AUTO + "\n\n" + construct_tool_use_system_prompt(tools)
  else:
    return SYSTEM_PROMPT_AUTO

functionary_tokenizer = None
def get_functionary_tokenizer(repo_id):
  global functionary_tokenizer
  if functionary_tokenizer is None:
    functionary_tokenizer = AutoTokenizer.from_pretrained(repo_id, legacy=True)
  return functionary_tokenizer

def process_tool_calls(interpreter, tool_calls):
  interpreter.messages.append({ "content": None, "tool_calls": tool_calls, "role": "assistant" })
  for tool_call in tool_calls:
    res = ''
    args = tool_call["function"]["arguments"]
    if type(args) is str:
      try:
        args = json.loads(args)
      except:
        builtins.print(f"Error parsing json: {args}")

    if tool_call["function"]["name"] == "r2cmd":
      if type(args) is str:
        args = { "command": args }
      if "command" in args:
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
    if (not res or len(res) == 0) and interpreter.model.startswith('meetkai/'):
      res = "OK done"
    interpreter.messages.append({"role": "tool", "content": ANSI_REGEX.sub('', res), "name": tool_call["function"]["name"], "tool_call_id": tool_call["id"] if "id" in tool_call else None})

def process_hermes_response(interpreter, response):
  choice = response["choices"][0]
  message = choice["message"]
  interpreter.messages.append(message)
  r = re.search(r'<tool_call>([\s\S]*?)<\/tool_call>', message["content"])
  tool_call_str = None
  if r:
    tool_call_str = r.group(1)
  tool_calls = []
  if tool_call_str:
    tool_call = json.loads(tool_call_str)
    tool_calls.append({"function": tool_call})

  if len(tool_calls) > 0:
    process_tool_calls(interpreter, tool_calls)
    chat(interpreter)
  else:
    interpreter.messages.append({ "content": message["content"], "role": "assistant" })
    sys.stdout.write(message["content"])
  builtins.print()

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
    interpreter.messages.insert(0,{"role": "system", "content": get_system_prompt(interpreter.model)})

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
  elif interpreter.model.startswith('anthropic:'):
    if not interpreter.anthropic_client:
      try:
        from anthropic import Anthropic
      except ImportError:
        print("pip install -U anthropic")
        return
      interpreter.anthropic_client = Anthropic()
    messages = []
    system_message = construct_tool_use_system_prompt(tools)
    for m in interpreter.messages:
      role = m["role"]
      if role == "system":
        continue
      if m["content"] is None:
        continue
      if role == "tool":
        messages.append({ "role": "user", "content": f"<function_results>\n<result>\n<tool_name>{m['name']}</tool_name>\n<stdout>{m['content']}</stdout>\n</result>\n</function_results>" })
        # TODO: handle errors
      else:
        messages.append({ "role": role, "content": m["content"] })

    stream = interpreter.anthropic_client.messages.create(
      model=interpreter.model[10:],
      max_tokens=int(interpreter.env["llm.maxtokens"]),
      messages=messages,
      system=system_message,
      temperature=float(interpreter.env["llm.temperature"]),
      stream=True
    )
    (tool_calls, msg) = extract_claude_tool_calls(interpreter, stream)
    if len(tool_calls) > 0:
      process_tool_calls(interpreter, tool_calls)
      chat(interpreter)
    else:
      builtins.print(msg)
  else:
    chat_format = interpreter.llama_instance.chat_format
    is_functionary = interpreter.model.startswith("meetkai/")
    if is_functionary:
      tokenizer = get_functionary_tokenizer(interpreter.model)
      prompt_templ = prompt_template.get_prompt_template_from_tokenizer(tokenizer)
      prompt_str = prompt_templ.get_prompt_from_messages(interpreter.messages + [{"role": "assistant"}], tools)
      token_ids = tokenizer.encode(prompt_str)
      stop_token_ids = [
        tokenizer.encode(token)[-1]
        for token in prompt_templ.get_stop_tokens_for_generation()
      ]
      gen_tokens = []
      for token_id in interpreter.llama_instance.generate(token_ids, temp=float(interpreter.env["llm.temperature"])):
        sys.stdout.write(tokenizer.decode([token_id]))
        if token_id in stop_token_ids:
            break
        gen_tokens.append(token_id)
      llm_output = tokenizer.decode(gen_tokens)
      response = prompt_templ.parse_assistant_response(llm_output)
      process_streaming_response(interpreter, iter([
        { "choices": [{ "message": response }] }
      ]))
    elif interpreter.model.startswith("NousResearch/"):
      interpreter.llama_instance.chat_format = "chatml"
      messages = []
      for m in interpreter.messages:
        role = m["role"]
        if m["content"] is None:
          continue
        if role == "system":
          if not '<tools>' in m["content"]:
            messages.append({ "role": "system", "content": f"""{m['content']}\nYou are a function calling AI model. You are provided with function signatures within <tools></tools> XML tags. You may call one or more functions to assist with the user query. Don't make assumptions about what values to plug into functions. Here are the available tools:
<tools> {json.dumps(tools)} </tools>
For each function call return a json object with function name and arguments within <tool_call></tool_call> XML tags as follows:
<tool_call>
{{"arguments": <args-dict>, "name": <function-name>}}
</tool_call>"""})
        elif role == "tool":
          messages.append({ "role": "tool", "content": "<tool_response>\n" + '{"name": ' + m['name'] + ', "content": ' + json.dumps(m['content']) + '}\n</tool_response>' })    
        else:
          messages.append(m)

      response = interpreter.llama_instance.create_chat_completion(
        max_tokens=int(interpreter.env["llm.maxtokens"]),
        messages=messages,
        temperature=float(interpreter.env["llm.temperature"]),
      )
      
      process_hermes_response(interpreter, response)
      interpreter.llama_instance.chat_format = chat_format

    else:
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
        # stream=is_functionary,
        temperature=float(interpreter.env["llm.temperature"]),
      )
      process_streaming_response(interpreter, iter([response]))
      interpreter.llama_instance.chat_format = chat_format
  return response
   
