import builtins
import json
import sys
import re
import os
import boto3

from llama_cpp import Llama
from llama_cpp.llama_tokenizer import LlamaHFTokenizer
from transformers import AutoTokenizer
from anthropic import Anthropic

from . import index
from .anthropic import construct_tool_use_system_prompt, extract_claude_tool_calls
from .backend.bedrock import (
    BEDROCK_TOOLS_CONFIG, build_messages_for_bedrock, extract_bedrock_tool_calls,
    process_bedrock_tool_calls, print_bedrock_response
)
from .pipe import have_rlang, r2lang, get_r2_inst

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
    matches = index.match(msg, keywords, datadir, False, False, False, False, use_vectordb)
    if matches == None:
        return ""
    # "(analyze using 'af', decompile using 'pdc')"
    return "context: " + ", ".join(matches)

def chat(interpreter):
    if len(interpreter.messages) == 1:
        interpreter.messages.insert(0, {
            "role": "system",
            "content": get_system_prompt(interpreter.model)
        })

    # chat_context = ""
    # try:
    #     lastmsg = interpreter.messages[-1]["content"]
    #     chat_context = context_from_msg (lastmsg)
    # except Exception:
    #     pass

    #print("#### CONTEXT BEGIN")
    #print(chat_context) # DEBUG
    #print("#### CONTEXT END")

    # if chat_context != "":
    #     interpreter.messages.insert(1, {"role": "user", "content": chat_context})

    response = None
    if interpreter.model.startswith("openai:"):
        if not interpreter.openai_client:
            try:
                from openai import OpenAI
            except ImportError:
                print("pip install -U openai", file=sys.stderr)
                print("export OPENAI_API_KEY=...", file=sys.stderr)
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

    elif interpreter.model.startswith("bedrock:"):
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

    elif interpreter.model.startswith("groq:"):
        if not interpreter.groq_client:
            try:
                from groq import Groq
            except ImportError:
                print("pip install -U groq", file=sys.stderr)
                return
            interpreter.groq_client = Groq()
        response = interpreter.groq_client.chat.completions.create(
            model=interpreter.model[5:],
            max_tokens=int(interpreter.env["llm.maxtokens"]),
            tools=tools,
            messages=interpreter.messages,
            tool_choice="auto",
            temperature=float(interpreter.env["llm.temperature"]),
        )
        process_streaming_response(interpreter, [response])

    elif interpreter.model.startswith("google"):
        if not interpreter.google_client:
            try:
                import google.generativeai as google
                google.configure(api_key=os.environ['GOOGLE_API_KEY'])
            except ImportError:
                print("pip install -U google-generativeai", file=sys.stderr)
                return
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

        else:
            chat_format = interpreter.llama_instance.chat_format
            is_functionary = interpreter.model.startswith("meetkai/")
            if is_functionary:
                try:
                    from .functionary import prompt_template
                except ImportError:
                    print("pip install -U functionary", file=sys.stderr)
                    return
                tokenizer = get_functionary_tokenizer(interpreter.model)
                prompt_templ = prompt_template.get_prompt_template_from_tokenizer(tokenizer)
                #print("############# BEGIN")
                #print(dir(prompt_templ))
                #print("############# MESSAGES")
                #print(interpreter.messages)
                #print("############# END")
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
