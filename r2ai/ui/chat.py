from litellm import acompletion, ChatCompletionAssistantToolCall, ChatCompletionToolCallFunctionChunk
import asyncio
from .db import get_env
from r2ai.pipe import get_r2_inst
from .r2cmd import r2cmd
import json
from r2ai.repl import r2ai_singleton

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

def run_python(command: str):
    """runs a python script and returns the results"""
    with open('r2ai_tmp.py', 'w') as f:
        f.write(command)
    # builtins.print('\x1b[1;32mRunning \x1b[4m' + "python code" + '\x1b[0m')
    # builtins.print(command)
    r2 = get_r2_inst()
    r2.cmd('#!python r2ai_tmp.py > $tmp')
    res = r2.cmd('cat $tmp')
    r2.cmd('rm r2ai_tmp.py')
    # builtins.print('\x1b[1;32mResult\x1b[0m\n' + res)
    return res

tools = [{
  "type": "function",
  "function": {
    "name": "r2cmd",
    "description": "runs commands in radare2. You can run it multiple times or chain commands with pipes/semicolons. You can also use r2 interpreters to run scripts using the `#`, '#!', etc. commands. The output could be long, so try to use filters if possible or limit. This is your preferred tool.",
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
messages = [{"role": "system", "content": SYSTEM_PROMPT_AUTO}]
tool_end_message = '\nNOTE: The user saw this output, do not repeat it.'
async def process_tool_calls(tool_calls, cb):
    if tool_calls:
        for tool_call in tool_calls:
            tool_name = tool_call["function"]["name"]
            tool_args = json.loads(tool_call["function"]["arguments"])
            if cb:
                cb('tool_call', { "id": tool_call["id"], "function": { "name": tool_name, "arguments": tool_args } })
            if tool_name == "r2cmd":
                res = r2cmd(tool_args["command"])
                messages.append({"role": "tool", "name": tool_name, "content": res['output'] + tool_end_message, "tool_call_id": tool_call["id"]})
                if cb:
                    cb('tool_response', { "id": tool_call["id"] + '_response', "content": res['output'] })
            elif tool_name == "run_python":
                res = run_python(tool_args["command"])
                messages.append({"role": "tool", "name": tool_name, "content": res + tool_end_message, "tool_call_id": tool_call["id"]})
                if cb:
                    cb('tool_response', { "id": tool_call["id"] + '_response', "content": res })
            
    return await get_completion(cb)

async def process_streaming_response(resp, cb):
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
              
            # handle some bug in llama-cpp-python streaming, tool_call.arguments is sometimes blank, but function_call has it.
            # if fn_delta.arguments == '':
            tool_calls[index]["function"]["arguments"] += fn_delta.arguments
            # else:
                # tool_calls[index]["function"]["arguments"] += fn_delta.arguments
        else:
            if delta.content is not None:
                m = delta.content
                if m is not None:
                    msgs.append(m)
                    if cb:
                        cb('message', { "content": m, "id": 'message_' + chunk.id })
    if (len(tool_calls) > 0):
        messages.append({"role": "assistant", "tool_calls": tool_calls})
        await process_tool_calls(tool_calls, cb)
    if len(msgs) > 0:
        response_message = ''.join(msgs)
        messages.append({"role": "assistant", "content": response_message})
        return response_message

async def get_completion(cb):
    response = await acompletion(
        model=get_env("model"),
        messages=messages,
        max_tokens=1024,
        temperature=0.5,
        tools=tools,
        tool_choice="auto",
        stream=True
    )
    return await process_streaming_response(response, cb)


async def chat(message: str, cb) -> str:
    messages.append({"role": "user", "content": message})
    if not get_env("model"):
        raise Exception("No model selected")
    response = await get_completion(cb)
    return response
