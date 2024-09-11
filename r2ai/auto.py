import builtins
import json
import sys
import re
import os
import boto3
import logging

from llama_cpp import Llama
from llama_cpp.llama_tokenizer import LlamaHFTokenizer
from transformers import AutoTokenizer
from anthropic import Anthropic
from openai import OpenAI, OpenAIError
from rich.console import Console

from . import index, LOGGER
from .anthropic import construct_tool_use_system_prompt, extract_claude_tool_calls
from .backend.bedrock import (
    BEDROCK_TOOLS_CONFIG, build_messages_for_bedrock, extract_bedrock_tool_calls,
    process_bedrock_tool_calls, print_bedrock_response
)
from .pipe import have_rlang, r2lang, get_r2_inst
from .utils import syscmdstr
logger = LOGGER.getChild("auto")

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
      },
      "required": ["command"]
    },
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
      },
      "required": ["command"]
    }
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
    if model.startswith("anthropic"):
        return SYSTEM_PROMPT_AUTO + "\n\n" + construct_tool_use_system_prompt(tools)
    return SYSTEM_PROMPT_AUTO

functionary_tokenizer = None
def get_functionary_tokenizer(repo_id):
    global functionary_tokenizer
    if functionary_tokenizer is None:
        functionary_tokenizer = AutoTokenizer.from_pretrained(repo_id, legacy=True)
    return functionary_tokenizer

def r2cmd(command: str):
    """runs commands in radare2. You can run it multiple times or chain commands
    with pipes/semicolons. You can also use r2 interpreters to run scripts using
    the `#`, '#!', etc. commands. The output could be long, so try to use filters
    if possible or limit. This is your preferred tool"""
    builtins.print('\x1b[1;32mRunning \x1b[4m' + command + '\x1b[0m')
    r2 = get_r2_inst()
    res = r2.cmd(command)
    builtins.print(res)
    return res

def run_python(command: str):
    """runs a python script and returns the results"""
    with open('r2ai_tmp.py', 'w') as f:
        f.write(command)
    builtins.print('\x1b[1;32mRunning \x1b[4m' + "python code" + '\x1b[0m')
    builtins.print(command)
    r2lang.cmd('#!python r2ai_tmp.py > $tmp')
    res = r2lang.cmd('cat $tmp')
    r2lang.cmd('rm r2ai_tmp.py')
    builtins.print('\x1b[1;32mResult\x1b[0m\n' + res)
    return res

def process_tool_calls(interpreter, tool_calls):
    interpreter.messages.append({ "content": None, "tool_calls": tool_calls, "role": "assistant" })
    for tool_call in tool_calls:
        res = ''
        args = tool_call["function"]["arguments"]
        if type(args) is str:
            try:
                args = json.loads(args)
            except Exception:
                builtins.print(f"Error parsing json: {args}", file=sys.stderr)
        if tool_call["function"]["name"] == "r2cmd":
            if type(args) is str:
                args = { "command": args }
            if "command" in args:
                res = r2cmd(args["command"])
        elif tool_call["function"]["name"] == "run_python":
            res = run_python(args["command"])
        if (not res or len(res) == 0) and interpreter.model.startswith('meetkai/'):
            res = "OK done"
        msg = {
            "role": "tool",
            "content": ANSI_REGEX.sub('', res),
            "name": tool_call["function"]["name"],
            "tool_call_id": tool_call["id"] if "id" in tool_call else None
        }
        interpreter.messages.append(msg)

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
        try:
            chunk = dict(chunk)
        except Exception:
            pass
        delta = None
        choice = dict(chunk["choices"][0])
        finish_reason = chunk["choices"][-1].finish_reason
        if finish_reason == "stop":
            tool_calls = []
            msgs = []
            break
        if "delta" in choice:
            delta = dict(choice["delta"])
        else:
            delta = dict(choice["message"])
        if "tool_calls" in delta and delta["tool_calls"]:
            delta_tool_calls = dict(delta["tool_calls"][0])
            index = 0 if "index" not in delta_tool_calls else delta_tool_calls["index"]
            fn_delta = dict(delta_tool_calls["function"])
            tool_call_id = delta_tool_calls["id"] or f"r2cmd"
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
    if (len(tool_calls) > 0):
        process_tool_calls(interpreter, tool_calls)
        chat(interpreter)
    if len(msgs) > 0:
        response_message = ''.join(msgs)
        interpreter.messages.append({"role": "assistant", "content": response_message})

def context_from_msg(msg):
    keywords = None
    datadir = "doc/auto"
    use_vectordb = False
    last_msg = None
    if isinstance(msg.get("content"), str):
        last_msg = msg["content"]
    elif isinstance(msg.get("content"), list):
        # Bedrock puts an array in the 'content' key, in that case unfold them in a single message
        last_msg = ". ".join([c["text"] for c in msg["content"] if "text" in c])

    if not last_msg:
        return None

    matches = index.match(last_msg, keywords, datadir, False, False, False, False, use_vectordb)
    if not matches:
        return None

    return "context: " + ", ".join(matches)

def chat(interpreter):
    if len(interpreter.messages) == 1:
        interpreter.messages.insert(0, {
            "role": "system",
            "content": get_system_prompt(interpreter.model)
        })

    chat_context = ""
    try:
        lastmsg = interpreter.messages[-1]
        chat_context = context_from_msg(lastmsg)
        # print(f"Adding context: {chat_context}")
    except Exception:
        pass

    if chat_context:
        interpreter.messages.append({"role": "user", "content": chat_context})

    platform, modelid = None, None
    if ":" in interpreter.model:
        if interpreter.model.startswith("openai:") or interpreter.model.startswith("openapi:"):
            if interpreter.model.startswith("openapi:"):
                uri = interpreter.model.split(":", 3)[1:]
                if len(uri) > 2:
                    interpreter.api_base = ":".join(uri[:-1])
                    modelid = uri[-1]
            else:
                modelid = interpreter.model.rsplit(":")[-1]
            platform = interpreter.model.split(":")[0]
        else:
            platform = interpreter.model.split(":")[0]
            modelid  = ":".join(interpreter.model.split(":")[1:])
    elif "/" in interpreter.model:
        platform = interpreter.model.split("/")[0]
        modelid  = "/".join(interpreter.model.split("/")[1:])
    auto_chat_handler_fn = None
    if modelid in auto_chat_handlers.get(platform, {}):
        auto_chat_handler_fn = auto_chat_handlers[platform][modelid]
    elif "default" in auto_chat_handlers.get(platform, {}):
        auto_chat_handler_fn = auto_chat_handlers[platform]["default"]

    if not auto_chat_handler_fn:
        print(f"Model {platform}:{modelid} is not currently supported in auto mode")
        return

    return auto_chat_handler_fn(interpreter)

def auto_chat_openai(interpreter):
    api_key = syscmdstr('cat ~/.r2ai.openai-key').strip();
    if not interpreter.openai_client:
        interpreter.openai_client = OpenAI(base_url=interpreter.api_base, api_key=api_key)
    response = "No response"
    if interpreter.model.startswith("openapi:"):
        uri = interpreter.model.split(":", 3)[1:]
        if len(uri) > 2:
            interpreter.api_base = ":".join(uri[:-1])
            model = uri[-1]
    else:
        model = interpreter.model.rsplit(":")[-1]
    try:
        response = interpreter.openai_client.chat.completions.create(
            model=model,
            max_tokens=int(interpreter.env["llm.maxtokens"]),
            tools=tools,
            messages=interpreter.messages,
            tool_choice="required",
            stream=True,
            temperature=float(interpreter.env["llm.temperature"]),
        )
        process_streaming_response(interpreter, response)
    
    except OpenAIError as e:
        logger.error("OpenAIError[%s]: %s", e.body['code'], e.body['message'])
        if LOGGER.level == logging.DEBUG:
            Console().print_exception()
        return
    except Exception as e:
        logger.error("Exception %s", e)
        if LOGGER.level == logging.DEBUG:
            Console().print_exception()
        return
    return response

def auto_chat_anthropic(interpreter):
    if not interpreter.anthropic_client:
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

def auto_chat_bedrock(interpreter):
    interpreter.bedrock_client = boto3.client("bedrock-runtime")
    model_id = interpreter.model.split(":")[1] + ":0"
    system_message = construct_tool_use_system_prompt(tools)

    response = interpreter.bedrock_client.converse(
        modelId=model_id,
        toolConfig=BEDROCK_TOOLS_CONFIG,
        messages=build_messages_for_bedrock(interpreter.messages),
        inferenceConfig={
            "maxTokens": int(interpreter.env["llm.maxtokens"]),
            "temperature": float(interpreter.env["llm.temperature"]),
            "topP": 0.9
        },
    )
    print_bedrock_response(response)
    # Update conversation
    interpreter.messages.append(response["output"]["message"])
    # Execute tools
    tool_calls = extract_bedrock_tool_calls(response)
    if tool_calls:
        tool_msgs = process_bedrock_tool_calls(tool_calls)
        interpreter.messages.extend(tool_msgs)
        chat(interpreter)

    return response

def auto_chat_groq(interpreter):
    if not interpreter.groq_client:
        interpreter.groq_client = Groq()

    response = interpreter.groq_client.chat.completions.create(
        model=interpreter.model[5:],
        max_tokens=int(interpreter.env["llm.maxtokens"]),
        tools=tools,
        messages=interpreter.messages,
        tool_choice="required",
        temperature=float(interpreter.env["llm.temperature"]),
    )
    process_streaming_response(interpreter, [response])
    return response

def auto_chat_google(interpreter):
    import google.generativeai as google

    response = None
    if not interpreter.google_client:
        google.configure(api_key=os.environ['GOOGLE_API_KEY'])
        interpreter.google_client = google.GenerativeModel(interpreter.model[7:])

    if not interpreter.google_chat:
        interpreter.google_chat = interpreter.google_client.start_chat(
            enable_automatic_function_calling=True
        )

    response = interpreter.google_chat.send_message(
        interpreter.messages[-1]["content"],
        generation_config={
            "max_output_tokens": int(interpreter.env["llm.maxtokens"]),
            "temperature": float(interpreter.env["llm.temperature"])
        },
        safety_settings=[{
            "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
            "threshold": "BLOCK_NONE"
        }],
        tools=[r2cmd, run_python]
    )
    print(response.text)
    return response

def auto_chat_nousresearch(interpreter):
    interpreter.llama_instance.chat_format = "chatml"
    messages = []
    for m in interpreter.messages:
        if m["content"] is None:
            continue
        role = m["role"]
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
        return response

def auto_chat_llama(interpreter):
    interpreter.llama_instance.chat_format = "chatml-function-calling"
    response = interpreter.llama_instance.create_chat_completion(
        max_tokens=int(interpreter.env["llm.maxtokens"]),
        tools=tools,
        messages=interpreter.messages,
        tool_choice="required",
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
    return response


auto_chat_handlers = {
    "openai": {
        "default": auto_chat_openai,
    },
    "openapi": {
        "default": auto_chat_openai,
    },
    "anthropic": {
        "default": auto_chat_anthropic
    },
    "bedrock": {
        "default": auto_chat_bedrock
    },
    "groq": {
        "default": auto_chat_groq
    },
    "google": {
        "default": auto_chat_google
    },
    "NousResearch": {
        "default": auto_chat_nousresearch
    },
    "llama": {
        "default": auto_chat_llama
    }
}