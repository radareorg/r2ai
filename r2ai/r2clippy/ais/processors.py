import json
import sys

from openai.types.chat import ChatCompletionChunk
from pydantic_core import ValidationError

from ... import LOGGER
from ..constants import ANSI_REGEX
from ..functions import PythonCmd, R2Cmd, validate_ai_tool

_retries = 0
_chunks = []  # workaround for  retrying


def process_streaming_response(interpreter, response, max_retries=0):
    try:
        return _process_streaming_response(interpreter, response)
    except Exception as e:
        global _retries
        if _retries == max_retries:
            raise e
        if not _chunks:
            raise e
        _retries += 1
        LOGGER.getChild("r2clippy").info("Got invalid response %s Retrying", e)
        choice = _chunks[-1].choices[0]
        if hasattr(choice, "delta"):
            delta = choice.delta
            if hasattr(delta, "tool_calls") and delta.tool_calls:
                delta_tool_calls = delta.tool_calls[0]
                fn_delta = delta_tool_calls.function
                tool_call_id = delta_tool_calls.id
                if tool_call_id is not None:
                    interpreter.messages.append(
                        {
                            "role": "tool",
                            "content": f"Validation Error found:\n{e}\nRecall the function correctly, fix the errors".strip(),
                            "name": fn_delta.name,
                            "tool_call_id": tool_call_id
                        }
                    )
                    return True
        interpreter.messages.append(
            {
                "role": "user",
                "content": f"Validation Error found:\n{e}\nRecall the function correctly, fix the errors".strip()
            }
        )
        return True


def _process_streaming_response(interpreter, response) -> bool:
    """Process streaming response.
    Returns True if a chat call should be done
    """
    tool_calls = []
    msgs = []
    chunk: ChatCompletionChunk
    global _chunks
    _chunks = []
    for chunk in response:
        _chunks.append(chunk)
        delta = None
        choice = chunk.choices[0]
        if hasattr(choice, "delta"):
            delta = choice.delta
        else:
            delta = choice.message
        if hasattr(delta, "tool_calls") and delta.tool_calls:

            delta_tool_calls = delta.tool_calls[0]
            index = 0 if not hasattr(
                delta_tool_calls, "index") else delta_tool_calls.index
            fn_delta = delta_tool_calls.function
            tool_call_id = delta_tool_calls.id or "r2cmd"
            if len(tool_calls) < index + 1:
                tool_calls.append({
                    "function": {
                        "arguments": "",
                        "name": fn_delta.name,
                    },
                    "id": tool_call_id,
                    "type": "function"
                })
            if not fn_delta.arguments:
                if hasattr(delta, "function_call") and delta.function_call:
                    tool_calls[index]["function"]["arguments"] += delta.function_call.arguments
            else:
                tool_calls[index]["function"]["arguments"] += fn_delta.arguments
        else:
            if hasattr(delta, "content") and delta.content:
                m = delta.content
                if m:
                    msgs.append(m)
                    sys.stdout.write(m)
    if len(tool_calls) > 0:
        process_tool_calls(interpreter, tool_calls)
        return True
    if len(msgs) > 0:
        response_message = ''.join(msgs)
        interpreter.messages.append({
            "role": "assistant",
            "content": response_message.strip()
        })
    return False


def process_tool_calls(interpreter, tool_calls):
    interpreter.messages.append(
        {
            "content": "Continue with task",
            "tool_calls": tool_calls,
            "role": "assistant"
        }
    )
    content = ""
    for tool in tool_calls:
        args = tool["function"]["arguments"]
        tool_name = tool["function"]["name"]
        tool_id = tool["id"] if "id" in tool else None
        if type(args) == str:
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                print(f"Error parsing json: {args}", file=sys.stderr)
        content = validate_ai_tool(args).result
        if not tool_name:
            raise ValueError("Tool name must not be null")
        if not tool_id:
            raise ValueError("Tool id must not be null")

        msg = {
            "role": "tool",
            "content": ANSI_REGEX.sub("", content.strip()),
            "name": tool_name,
            "tool_call_id": tool_id
        }
        interpreter.messages.append(msg)
