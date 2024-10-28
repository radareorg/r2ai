import sys
import traceback
from . import LOGGER
import json
from llama_cpp.llama_types import *
from llama_cpp.llama_grammar import LlamaGrammar
from llama_cpp.llama import StoppingCriteriaList, LogitsProcessorList
from typing import List, Iterator, Dict, Any, Optional, Union, Callable, Sequence, Generator
import uuid
import llama_cpp
import re
from .partial_json_parser import parse_incomplete_json

def messages_to_prompt(self, messages, tools=None):
    for message in messages:
        # Happens if it immediatly writes code
        if "role" not in message:
            message["role"] = "assistant"
    lowermodel = self.model.lower()
    if "q4_0" in lowermodel:
        formatted_messages = template_q4im(self, messages)
    elif "gemma" in lowermodel:
        formatted_messages = template_gemma(self, messages)
    elif "granite" in lowermodel:
        formatted_messages = template_granite(self, messages)
    elif "starcoder" in lowermodel:
        formatted_messages = template_starcoder(self, messages)
    elif "openchat" in lowermodel:
        formatted_messages = template_openchat(self, messages)
    elif "ferret" in lowermodel:
        formatted_messages = template_ferret(self, messages)
    elif "tief" in lowermodel:
        formatted_messages = template_tiefighter(self, messages)
    elif "luna" in lowermodel:
        formatted_messages = template_alpaca(self, messages)
    elif "zephyr" in lowermodel:
        formatted_messages = template_zephyr(self, messages)
    elif "astra" in lowermodel:
        formatted_messages = template_granite(self, messages)
    elif "dolphin" in lowermodel:
        formatted_messages = template_ferret(self, messages)
    elif "phi" in lowermodel:
        formatted_messages = template_phi3(self, messages)
    elif "coder" in lowermodel:
        formatted_messages = template_alpaca(self, messages)
    elif "deepseek" in lowermodel:
        formatted_messages = template_alpaca(self, messages)
    elif "llama-3.2" in lowermodel or "llama-3.1" in lowermodel:
        formatted_messages = template_llama31(self, messages, tools)
    elif "llama-3" in lowermodel:
        formatted_messages = template_llama3(self, messages)
    elif "functionary" in lowermodel and 'v3.1' in lowermodel:
        formatted_messages = template_functionary_v31(self, messages, tools)
    elif "functionary" in lowermodel and 'v3.2' in lowermodel:
        formatted_messages = template_functionary_v32(self, messages, tools)
    elif 'qwen' in lowermodel:
        formatted_messages = template_qwen(self, messages, tools)
    elif "uncensor" in lowermodel:
        # formatted_messages = template_gpt4all(self, messages)
        # formatted_messages = template_alpaca(self, messages)
        formatted_messages = template_uncensored(self, messages)
        # formatted_messages = template_gpt4all(self, messages)
    elif "gpt4all" in lowermodel:
        formatted_messages = template_gpt4all(self, messages)
    elif "falcon" in lowermodel:
        formatted_messages = template_falcon(self, messages)
    elif "utopia" in lowermodel:
        formatted_messages = template_alpaca(self, messages)
    elif "holy" in lowermodel:
        formatted_messages = template_alpaca(self, messages)
    elif "mistral" in lowermodel:
        formatted_messages = template_mistral(self, messages)
    elif "python" in lowermodel:
        print("codellama-python model is not working well yet", file=sys.stderr)
        formatted_messages = template_llamapython(self, messages)
    elif "tinyllama" in lowermodel:
        formatted_messages = template_tinyllama(self, messages)
    else:
        formatted_messages = template_llama(self, messages)
    LOGGER.debug(formatted_messages)
    return formatted_messages

def response_to_message(self, response):
    lowermodel = self.model.lower()
    if "llama-3.2" in lowermodel or "llama-3.1" in lowermodel:
        return response_llama31(self, response)
    elif "functionary" in lowermodel and 'v3.1' in lowermodel:
        return response_functionary_v31(self, response)
    elif "functionary" in lowermodel and 'v3.2' in lowermodel:
        return response_functionary_v32(self, response)
    elif 'qwen' in lowermodel:
        return response_qwen(self, response)
    else:
        print("This model has not been tested with auto mode yet. Defaulting to llama-3.1", file=sys.stderr)
        return response_llama31(self, response)


def template_granite(self,messages):
    self.terminator = ["Question:", "Answer:"]
    msg = ""
    try:
        if self.system_message != "":
            msg += f"System:\n{self.system_message}\n"
        for index, item in enumerate(messages):
            role = item['role']
            content = item['content'].strip()
            if not role:
                role = "user"
            elif role == "hint":
                role = "user"
                content = f"Use this information to respond the question:{content}"
            if content != "":
                msg += f"Question:\n{content}\n"
        msg += f"Answer:\n"
    except Exception:
        traceback.print_exc()
    return msg

def template_qwen(self, messages, tools):
    system_prompt = self.system_message or ""
    formatted_messages = ""
    if messages[0]['role'] == 'system':
        system_prompt += messages[0]['content']
    formatted_messages += f"<|im_start|>system\n{system_prompt}"
    if tools:
        formatted_messages += f"\n\n## Tools\n\nYou have access to the following tools:\n\n"
        function_names = []
        for tool in tools:
            fn = tool['function']
            function_names.append(fn['name'])
            formatted_messages += f"### {fn['name']}\n\n{fn['name']}: {fn['description']} Parameters: {json.dumps(fn['parameters'])} Format the arguments as a JSON object.\n\n"
        formatted_messages += f"""## When you need to call a tool, please insert the following command in your reply, which can be called zero or multiple times according to your needs:
            
✿FUNCTION✿: The tool to use, should be one of [{", ".join(function_names)}]
✿ARGS✿: The input of the tool
✿RESULT✿: Tool results
✿RETURN✿: Reply based on tool results. Images need to be rendered as ![](url)"""

    for index, item in enumerate(messages):
        role = item['role']
        if role == 'system':
            continue
        formatted_messages += f"<|im_start|>{role if role != 'tool' else 'user'}\n"
        if role == 'assistant':
            if 'tool_calls' in item:
                for tool_call in item['tool_calls']:
                    args = tool_call['function']['arguments']
                    if type(args) != str:
                        args = json.dumps(args)
                    formatted_messages += f"✿FUNCTION✿: {tool_call['function']['name']}\n✿ARGS✿: {args}\n"
            formatted_messages += f"{item['content']}"
        elif role == 'tool':
            formatted_messages += f"\n✿RESULT✿: {item['content'] or 'NO RESULT'}"
        else:
            formatted_messages += f"{item['content']}"
        formatted_messages += f"<|im_end|>"
    formatted_messages += f"<|im_start|>assistant\n"
    return formatted_messages

def template_gemma(self,messages):
    self.terminator = "<end_of_turn>"
    msg = ""
    try:
        if self.system_message != "":
            msg += f"<start_of_turn>system\n{self.system_message}<end_of_turn>"
        for index, item in enumerate(messages):
            role = item['role']
            content = item['content'].strip()
            if not role:
                role = "user"
            elif role == "hint":
                role = "user"
                content = f"Use this information to respond the question:{content}"
            if content != "":
                msg += f"<start_of_turn>{role}\n{content}<end_of_turn>\n"
        msg += f"<start_of_turn>model\n"
    except Exception:
        traceback.print_exc()
    return msg

def template_q4im(self,messages):
    self.terminator = "<|im_end|>"
    formatted_messages = ""
    try:
        system_prompt = messages[0]['content'].strip()
        if system_prompt != "":
            # formatted_messages += "\{\"text\":\"{"+system_prompt+"}\"\}"
            formatted_messages += f"<|im_start|>assistant {system_prompt}<|im_end|>"
            # formatted_messages += f"<|im_start|>system\n{system_prompt}<|im_end|>"
            # formatted_messages = f"[STDIN] {system_prompt} [/STDIN]\n"
            # formatted_messages = f"/imagine prompt: {system_prompt}\n"
        for index, item in enumerate(messages[1:]):
            role = item['role']
            content = item['content'].strip()
            formatted_messages += f"<|im_start|>user\n{content}<|im_end|>"
            # formatted_messages += f"<|im_start|>{content}<|im_end|>"
            # formatted_messages += "{\"text\":\"{"+content+"}\"}"
        formatted_messages += f"<|im_start|>\n"
        print("```" + formatted_messages + "```")
    except Exception:
        traceback.print_exc()
    return formatted_messages

def template_mistral(self, messages):
    # https://docs.mistral.ai/llm/mistral-instruct-v0.1
    self.terminator = "</s>"
    msg = "<s>"
    try:
        system_prompt = messages[0]['content'].strip()
        if system_prompt != "":
            msg += f"[INST]{system_prompt}[/INST]"
        for index, item in enumerate(messages[1:]):
            # print(item)
            role = item['role']
            if "content" not in item:
                continue
            content = item['content'].strip()
            if role == "user":
                msg += f"[INST]{content}[/INST]"
            elif role == "hint":
                msg += f"[INST]* {content}[/INST]"
            elif role == "assistant" and self.env["chat.reply"] == "true":
                if 'content' in item:
                    content = item['content'].strip()
                    msg += f"{content}."
    except Exception:
        traceback.print_exc()
    return msg

def template_uncensored(self, messages):
    #{'role': 'function', 'name': 'run_code', 'content': 'User decided not to run this code.'}
    #{'role': 'user', 'content': 'tenis'}
    #{'content': "\nI'm here to help you with any questions or tasks you have! What can I assist you with today?", 'role': 'assistant'}
    #{'role': 'user', 'content': "thehre's no purpose on this"}
    #{'role': 'assistant'}
    #{'role': 'user', 'content': 'force a crash'}
    self.terminator = "</s>"
    formatted_messages = "<s>"
    try:
        system_prompt = messages[0]['content'].strip()
        if system_prompt != "":
            formatted_messages = f"### Human: {system_prompt}\n"
            # formatted_messages = f"/imagine prompt: {system_prompt}\n"
        for index, item in enumerate(messages[1:]):
            # print(item)
            role = item['role']
            if role == "user":
                content = item['content'].strip()
                formatted_messages += f"### Human: {content}\n"
            elif role == "hint":
                formatted_messages += f"### Knowledge: {content}\n"
            elif role == "assistant" and self.env["chat.reply"] == "true":
                if 'content' in item:
                    content = item['content'].strip()
                    # formatted_messages += f"### Assistant: {content}\n"
                    formatted_messages += f"{content}\n"
        formatted_messages += f"### Assistant:"
        # print("```" + formatted_messages + "```")
    except Exception:
        traceback.print_exc()
    return formatted_messages

def template_falcon(self,messages):
    self.terminator = "}";
    formatted_messages = ""
    for message in messages:
        formatted_messages += f"{message['role'].capitalize()}: {message['content']}"
    return formatted_messages.strip()

def template_phi3(self,messages):
    self.terminator = "<|end|>"
    system_prompt = self.system_message # messages[0]['content'].strip()
    if system_prompt != "":
        q = f"<|assistant|>\n{system_prompt}<|end|>\n"
    else:
        q = f""
    for index, item in enumerate(messages):
        role = item['role']
        content = item['content']
        if role == 'user':
            q += f"<|user|>\n{content}<|end|>"
        elif role == "hint":
            q += f"knowledge: {content}\n"
        elif role == 'function':
            q += f"user {content} "
        elif role == 'assistant' and self.env["chat.reply"] == "true":
            q += f"<|assistant|>\n{content}<|end|>\n"
    q += f"<|assistant|>\n"
    return q

def template_starcoder(self,messages):
    self.terminator = "<|im_end|>"
    self.terminator = "##"
    system_prompt = self.system_message # messages[0]['content'].strip()
    if system_prompt != "":
        q = f"<|system|>\n{system_prompt}</s>\n"
    else:
        q = f""
    for index, item in enumerate(messages):
        role = item['role']
        content = item['content']
        if role == 'user':
            q += f"## Question\n{content}"
        elif role == "hint":
            q += f"knowledge: {content}\n"
        elif role == 'function':
            q += f"## Question\n{content} "
        elif role == 'assistant' and self.env["chat.reply"] == "true":
            q += f"## Solution\n{content}\n"
    q += f"## Solution\n"
    return q

def template_zephyr(self,messages):
    #<|system|>
    #{system_message}</s>
    #<|user|>
    #{prompt}</s>
    #<|assistant|>
    self.terminator = "</s>"
    system_prompt = self.system_message # messages[0]['content'].strip()
    if system_prompt != "":
        q = f"<|system|>\n{system_prompt}</s>\n"
    else:
        q = f""
    for index, item in enumerate(messages):
        role = item['role']
        content = item['content']
        if role == 'user':
            q += f"<|user|>\n{content}<|im_end|>"
        elif role == "hint":
            q += f"knowledge: {content}\n"
        elif role == 'function':
            q += f"user {content} "
        elif role == 'assistant' and self.env["chat.reply"] == "true":
            q += f"<|assistant|>\n{content}\n</s>\n"
    q += f"<|assistant|>\n"
    return q

def template_openchat(self,messages):
    self.terminator = "<|end_of_turn|>"
    system_prompt = self.system_message # messages[0]['content'].strip()
    if system_prompt != "":
        #q = f"<|im_start|>\n{system_prompt}\n<|im_end|>"
        q = f"{system_prompt}<|end_of_turn|>"
    else:
        q = f""
    for index, item in enumerate(messages):
        role = item['role']
        content = item['content']
        if role == 'user':
            q += f"Human: {content}<|end_of_turn|>"
        elif role == "hint":
  # q += f"knowledge: {content}\n"
            q += f"{content}<|end_of_turn|>"
        elif role == 'function':
            q += f"{content} "
        elif role == 'assistant' and self.env["chat.reply"] == "true":
            q += f"Assistant: {content}<|end_of_turn|>"
    q += f"Assistant: "
    # print(q)
    return q

def template_ferret(self,messages):
    self.terminator = "<|im_end|>"
    system_prompt = self.system_message # messages[0]['content'].strip()
    if system_prompt != "":
        #q = f"<|im_start|>\n{system_prompt}\n<|im_end|>"
        q = f"<|im_start|>system\n{system_prompt}\n<|im_end|>\n"
    else:
        q = f""
    for index, item in enumerate(messages):
        role = item['role']
        content = item['content']
        if role == 'user':
            q += f"<|im_start|>user\n{content}<|im_end|>"
        elif role == "hint":
  # q += f"knowledge: {content}\n"
            q += f"<|im_start|>hint\n{content}<|im_end|>"
        elif role == 'function':
            q += f"user {content} "
        elif role == 'assistant' and self.env["chat.reply"] == "true":
            q += f"<|im_start|>assistant\n{content}\n<|im_end|>\n"
    q += f"<|im_start|>assistant\n"
    # print(q)
    return q

def template_tinyllama(self,messages):
    # Llama prompt template
    # Extracting the system prompt and initializing the formatted string with it.
    self.terminator = "\n" # <|im_end|>"
    # TheBloke/TinyLlama-1.1B-Chat-v0.3-GGUF
    # <|></SENT>
    system_prompt = messages[0]['content'].strip()
    if system_prompt != "":
        formatted_messages = f"<|im_start|> assistant\n{system_prompt}\n<|im_end|>"
    else:
        formatted_messages = f"<|im_start|> "
    # Loop starting from the first user message
    for index, item in enumerate(messages[1:]):
        role = item['role']
        content = item['content']
        if role == 'user':
            formatted_messages += f"user {content} "
        elif role == "hint":
            formatted_messages += f"knowledge: {content}\n"
        elif role == 'function':
            formatted_messages += f"user {content} "
        elif role == 'assistant' and self.env["chat.reply"] == "true":
            formatted_messages += f"assistant {content} "
    # Remove the trailing '<s>[INST] ' from the final output
    formatted_messages += f"<|im_end|>"
    return formatted_messages

def template_llamapython(self, messages):
    self.terminator = "[/INST]"
    system_prompt = messages[0]['content'].strip()
    if system_prompt != "":
        formatted_messages = f"Comment: {system_prompt}.\n[INST]\n"
    else:
        formatted_messages = "[INST]\n"
    # Loop starting from the first user message
    for index, item in enumerate(messages[1:]):
        role = item['role']
        content = item['content']
        if role == 'user':
            formatted_messages += f"{content}\n[/INST]"
        elif self.env["chat.reply"] == "true":
            formatted_messages += f"[INST]Answer: {content}\n[/INST]"
    formatted_messages += "\n[INST]Answer: "
    return formatted_messages

def template_tiefighter(self, messages):
    self.terminator = "</s>"
    system_prompt = messages[0]['content'].strip()
    if system_prompt != "":
        formatted_messages = f"[Instructions]: {system_prompt}\n"
    else:
        formatted_messages = ""
    # Loop starting from the first user message
    for index, item in enumerate(messages[1:]):
        role = item['role']
        if not 'content' in item:
            continue
        content = item['content']
        if content is None or content == "":
            continue
        content = content.strip()
        if role == 'user':
            formatted_messages += f"[Instructions] {content} [/Instructions]\n"
        elif self.env["chat.reply"] == "true":
            formatted_messages += f"[Assistant] {content}\n"
  #         formatted_messages += f"### Response:\n{content}\n"
    formatted_messages += f"[Assistant]"
    return formatted_messages

def template_alpaca(self, messages):
    self.terminator = "###"
    system_prompt = self.system_message
    if len(system_prompt) > 1:
        formatted_messages = f"### Instruction: {system_prompt}\n"
    else:
        formatted_messages = ""
    formatted_messages += messages[0]['content'].strip()
    formatted_messages += "\n"
    # Loop starting from the first user message
    for index, item in enumerate(messages[1:]):
        if "content" in item and "role" in item:
            content = item['content']
        else:
            continue
        role = item['role']
        if content is None or content == "":
            continue
        content = content.strip()
        if role == 'user':
            formatted_messages += f"### Instruction: {content}\n"
        elif role == 'hint':
            formatted_messages += f"### Knowledge: {content}\n"
        elif self.env["chat.reply"] == "true":
            formatted_messages += f"### Assistant: {content}\n"
  #         formatted_messages += f"### Response:\n{content}\n"
    formatted_messages += f"### Response: "
    return formatted_messages

def template_gpt4all(self,messages):
    self.terminator = "###"
    system_prompt = messages[0]['content'].strip()
    if len(system_prompt) > 1:
        formatted_messages = f"### Instruction: {system_prompt}\n"
    else:
        formatted_messages = ""
    # Loop starting from the first user message
    for index, item in enumerate(messages[1:]):
        role = item['role']
        content = item['content']
        if content is None or content == "":
            continue
        content = content.strip()
        if role == 'user':
            formatted_messages += f"### User: {content}\n"
        elif self.env["chat.reply"] == "true":
            formatted_messages += f"### System: {content}\n"
    formatted_messages += f"### System: "
    return formatted_messages

def template_llama3(self,messages):
    formatted_messages = "" # f"<|begin_of_text|>"
    if self.system_message != "":
        formatted_messages += f"<|start_header_id|>system<{self.system_message}<|end_header_id|>"
        formatted_messages += f"<{self.system_message}<|eot_id|>"
    self.terminator = "<|eot_id|>"
    for index, item in enumerate(messages):
        if "role" in item:
            role = item['role']
        else:
            role = 'user'
        if "content" not in item:
            continue
        content = item['content']
        if role == 'user':
            formatted_messages += f"<|start_header_id|>user<|end_header_id|>"
            formatted_messages += f"{content}<|eot_id|>"
        elif role == 'hint':
            formatted_messages += f"<|start_header_id|>user<|end_header_id|>"
            formatted_messages += f"Hint: {content}<|eot_id|> "
        elif role == 'function':
            formatted_messages += f"<|start_header_id|>user<|end_header_id|>"
            formatted_messages += f"Function: {content}<|eot_id|> "
        elif role == 'assistant' and self.env["chat.reply"] == "true":
            formatted_messages += f"<|start_header_id|>assistant<|end_header_id|>"
            formatted_messages += f"{content}<|eot_id|>"
    formatted_messages += f"<|start_header_id|>assistant<|end_header_id|>"
    return formatted_messages

def template_llama31(self,messages, tools):
    formatted_messages = "" # f"<|begin_of_text|>"
    system_message = ""
    if tools is not None:
        system_message += """

Environment: ipython

You are an expert in composing functions. You are given a question and a set of possible functions.
Based on the question, you will need to make one or more function/tool calls to achieve the purpose.

If you decide to invoke any of the function(s), you MUST put it in the format of <|python_tag|>{ "name": "func_name", "parameters": {"param_name1": "param_value1", "param_name2": "param_value2"}}
You SHOULD NOT include any other text in the response.

Here is a list of functions in JSON format that you can invoke:

"""
        system_message += json.dumps([tool["function"] for tool in tools])

    if self.system_message != "" and self.system_message is not None:
        system_message += self.system_message
    user_message = None
    if messages[0]['role'] == 'system':
        system_message += messages[0]['content']
    if system_message != "":
        formatted_messages += f"<|start_header_id|>system<|end_header_id|>"
        formatted_messages += f"{system_message}"
        formatted_messages += "<|eot_id|>"

    for index, item in enumerate(messages):
        role = item['role']
        if role == 'tool':
            role = 'ipython'
        if role == 'system':
            continue
        formatted_messages += f"<|start_header_id|>{role}<|end_header_id|>"
        if 'tool_calls' in item:
            for tool_call in item['tool_calls']:
                formatted_messages += "\n\n<|python_tag|>" + json.dumps({ "name": tool_call['function']['name'], "parameters": tool_call['function']['arguments'] })
                formatted_messages += "\n<|eom_id|>"
        else:
            content = item['content'].strip()
            if role == 'ipython':
                formatted_messages += "\n\n"
                if content == "":
                    formatted_messages += 'NO RESULTS'
            formatted_messages += content
            formatted_messages += "<|eot_id|>"
    formatted_messages += f"<|start_header_id|>assistant<|end_header_id|>"
    return formatted_messages

def delta_text(id, text):
    return { "id": id, "choices": [{ "delta": { "content": text } }] }

def delta_tool_call(id, tool_call_id, name, params):
    return { "id": id, "choices": [{ "delta": { "tool_calls": [{ "function": {"name": name, "arguments": params}, "id": tool_call_id, "type": "function", "index": 0 }] } }] }

def response_llama31(self, response):
    full_text = ""
    tool_call_text_index = -1
    tool_call_id = None
    tool_call = None
    message = None
    id = str(uuid.uuid4())
    for text in response:
        full_text += text
        if text == "<|python_tag|>":
            tool_call_text_index = len(full_text)
            continue
        elif tool_call_text_index == -1:
            message = delta_text(id, text)
        else:
            function_call_json = full_text[tool_call_text_index:].strip()
            
            try:
                function_call = parse_incomplete_json(function_call_json)
                
                if function_call is not None:
                    if 'name' in function_call and not tool_call_id:
                        tool_call_id = str(uuid.uuid4())
                        message = delta_tool_call(id, tool_call_id, function_call["name"], None)
                    elif 'parameters' in function_call:
                        params = function_call["parameters"]
                        if type(params) == str:
                            params = params.replace('\\"', '"')
                        elif type(params) == dict:
                            params = json.dumps(params)
                        tool_call = delta_tool_call(id, tool_call_id, function_call["name"], params)
            except Exception:
                message = delta_text(id, text)
        yield message
    if tool_call is not None:
        yield tool_call
    yield { "id": id, "choices": [{ "finish_reason": "stop" }] }

def response_qwen(self, response):
    id = str(uuid.uuid4())
    full_text = ""
    lines = []
    curr_line = ""
    fn_call = None
    for text in response:
        full_text += text

        if text == "\n":
            if curr_line.startswith("✿FUNCTION✿:"):
                fn_call = { 'name': curr_line[11:].strip(), 'id': str(uuid.uuid4()), 'arguments': None }
            elif curr_line.startswith("✿ARGS✿:"):
                fn_call['arguments'] = curr_line[7:].strip().replace('\\"', '"')
                yield delta_tool_call(id, fn_call['id'], fn_call['name'], fn_call['arguments'])
            lines.append(curr_line)
            curr_line = ""
        else:
            curr_line += text
        if curr_line.startswith("✿"):
            continue
        yield delta_text(id, text)

    if curr_line.startswith("✿ARGS✿:") and fn_call is not None:
        fn_call['arguments'] = curr_line[7:].strip().replace('\\"', '"')
        yield delta_tool_call(id, fn_call['id'], fn_call['name'], fn_call['arguments'])

    yield { "id": id, "choices": [{ "finish_reason": "stop" }] }

def parse_functionary31_calls(input_str):
    pattern = re.compile(
        r'<function=(?P<func_name>[^>]+)>\s*(?P<params>(\"|\').*?(\"|\'))\s*</function>|<function=(?P<func_name2>[^>]+)>\s*(?P<params2>\{.*?\})\s*</function>',
        re.DOTALL
    )

    matches = pattern.finditer(input_str)
    parsed_functions = []

    for match in matches:
        if match.group('func_name') and match.group('params'):
            func_name = match.group('func_name').strip()
            params_str = match.group('params').strip()
        elif match.group('func_name2') and match.group('params2'):
            func_name = match.group('func_name2').strip()
            params_str = match.group('params2').strip()
        else:
            continue  # Skip if no valid match

        if not func_name:
            raise ValueError("Function name is missing in one of the function strings.")

        if not params_str:
            raise ValueError(f"Parameters JSON is missing for function '{func_name}'.")

        # Handle parameters wrapped in quotes
        if (params_str.startswith('"') and params_str.endswith('"')) or (params_str.startswith("'") and params_str.endswith("'")):
            # Strip the surrounding quotes
            params_str = params_str[1:-1]
            # Unescape any escaped characters
            params_str = bytes(params_str, "utf-8").decode("unicode_escape")

        # Parse the JSON parameters
        try:
            params = json.loads(params_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON for parameters in function '{func_name}': {e}")

        parsed_functions.append((func_name, params))

    if not parsed_functions:
        return None

    return parsed_functions

def serialize_functionary31_call(name, params):
    return f"<function={name}>{json.dumps(params)}</function>"

def response_functionary_v31(self, response):
    full_text = ""
    id = str(uuid.uuid4())
    in_function = False
    for text in response:
        full_text += text
        if '<function' in full_text:
            in_function = True
        tool_calls = parse_functionary31_calls(full_text)
        if tool_calls is not None:
            for (name, params) in tool_calls:
                tool_call_id = str(uuid.uuid4())
                yield {
                    "id": id,
                    "choices": [{
                        "delta": {
                            "tool_calls": [{
                                "id": tool_call_id,
                                "type": "function",
                                "index": 0,
                                "function": {
                                    "name": name,
                                    "arguments": params
                                }
                            }]
                        }
                    }]
                }
        elif not in_function:
            yield { "id": id, "choices": [{ "delta": { "content": text } }] }
    yield { "id": id, "choices": [{ "finish_reason": "stop" }] }

def parse_functionary32_calls(input_str):
    # Regular expression to split the string at each '>>>'
    # It captures the tool name or recipient after '>>>'
    parts = re.split(r'>>>(\w+)', input_str)
    
    content = ""
    tool_calls = []
    
    # The first element in 'parts' is the content before the first '>>>'
    if parts[0]:
        content += parts[0].strip()
    
    # Iterate over the split parts
    # 'parts' alternates between tool names/recipients and their corresponding data
    for i in range(1, len(parts), 2):
        name = parts[i].strip()
        if i + 1 < len(parts):
            data = parts[i + 1].strip()
            if name.lower() == 'all':
                # If the name is 'all', treat the following data as additional content
                if content:
                    content += " " + data
                else:
                    content = data
            else:
                # Assume it's a tool call with JSON parameters
                try:
                    parameters = json.loads(data)
                    tool_calls.append({
                        'name': name,
                        'parameters': parameters
                    })
                except json.JSONDecodeError:
                    pass

    return {
        'content': content,
        'tool_calls': tool_calls if len(tool_calls) > 0 else None
    }

def serialize_functionary32_calls(structure):
    content = structure.get('content', None)
    tool_calls = structure.get('tool_calls', [])
    
    parts = []
    
    if content:
        content = content.strip()
        parts.append(f'>>>all\n{content}')
    
    for tool in tool_calls:
        name = tool.get('name', '').strip()
        parameters = tool.get('arguments', "")
        
        # Serialize parameters to JSON string
        try:
            if type(parameters) == str:
                parameters_str = parameters
            else:
                parameters_str = json.dumps(parameters, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid parameters for tool '{name}': {e}")
        
        # Append the tool call with '>>>tool_name' followed by a newline and the parameters
        parts.append(f'>>>{name}\n{parameters_str}')
    
    # Join all parts without any additional separators
    serialized_str = ''.join(parts)
    
    return serialized_str


def template_functionary_v32(self, messages, tools):
    formatted_messages = "" # f"<|begin_of_text|>"
    system_message = ""
    tool_system_message = ""
    if tools is not None:
        tools_str = ""
        for tool in tools:
            params_str = ", ".join([f"// {param.get('description', param_name)}\n{param_name}: {param.get('type', '')}" for param_name, param in tool['function']['parameters']['properties'].items() if isinstance(param, dict)])
            tools_str += f"// {tool['function']['description']}\ntype {tool['function']['name']} = (_: {{\n{params_str}\n}}) => any;\n\n"

        tool_system_message += f"""

You are capable of executing available function(s) if required.
Only execute function(s) when absolutely necessary.
Ask for the required input to:recipient==all
Use JSON for function arguments.
Respond in this format:
>>>${{recipient}}
${{content}}
Available functions:
// Supported function definitions that should be called when necessary.
namespace functions {{

{tools_str}
}} // namespace functions"""

    if self.system_message != "" and self.system_message is not None:
        system_message += self.system_message
    user_message = None
    if messages[0]['role'] == 'system':
        system_message += messages[0]['content']
    if system_message != "":
        formatted_messages += f"<|start_header_id|>system<|end_header_id|>"
        formatted_messages += f"{system_message}"
        formatted_messages += "<|eot_id|>"
    if tool_system_message != "":
        formatted_messages = f"<|start_header_id|>system<|end_header_id|>{tool_system_message}<|eot_id|>" + formatted_messages
    last_tool_call = None
    prev_tool_call = None
    for index, item in enumerate(messages):
        role = item['role']
        if role == 'system':
            continue
        formatted_messages += f"<|start_header_id|>{role}<|end_header_id|>"
        if 'tool_calls' in item:
            for tool_call in item['tool_calls']:
                formatted_messages += '\n\n' + serialize_functionary32_calls({ "content": item['content'], "tool_calls": [tool_call['function']] })
                formatted_messages += "<|eot_id|>"
                prev_tool_call = last_tool_call
                last_tool_call = tool_call['function']

        else:
            content = item['content'].strip()
            if role == 'tool':
                if content != "":
                    formatted_messages += "\n\n" + content
                else:
                    formatted_messages += "\n\nNO RESULTS"
            else:
                formatted_messages += content
            formatted_messages += "<|eot_id|>"
    formatted_messages += f"<|start_header_id|>assistant<|end_header_id|>"
    return formatted_messages

def response_functionary_v32(self, response):
    full_text = ""
    id = str(uuid.uuid4())
    tool_calls = None
    in_function_call = False
    for text in response:
        message = None
        full_text += text
        if not in_function_call and re.search(r'>>>(?!all)', full_text):
            in_function_call = True
        if not in_function_call:
            message = delta_text(id, text)
        if in_function_call:
            tool_calls = parse_functionary32_calls(full_text)['tool_calls']
        if message is not None:
            yield message

    if tool_calls is not None:
        for tool_call in tool_calls:
            tool_call_id = str(uuid.uuid4())
            yield delta_tool_call(id, tool_call_id, tool_call['name'], tool_call['parameters'])

    yield { "id": id, "choices": [{ "finish_reason": "stop" }] }

def template_functionary_v31(self, messages, tools):
    formatted_messages = "" # f"<|begin_of_text|>"
    system_message = ""
    if tools is not None:
        tools_str = ""
        for tool in tools:
            tools_str += f"Use the function '{tool['function']['name']}' to {tool['function']['description']}\n"
            tools_str += json.dumps(tool['function']) + "\n\n"
        system_message += f"""

Cutting Knowledge Date: December 2023


You have access to the following functions:

{tools_str}
Think very carefully before calling functions.
If a you choose to call a function ONLY reply in the following format:
<{{start_tag}}={{function_name}}>{{parameters}}{{end_tag}}
where

start_tag => `<function`
parameters => a JSON dict with the function argument name as key and function argument value as value.
end_tag => `</function>`

Here is an example,
{serialize_functionary31_call("example_function_name", {"example_name": "example_value"})}

"""

    if self.system_message != "" and self.system_message is not None:
        system_message += self.system_message
    user_message = None
    if messages[0]['role'] == 'system':
        system_message += messages[0]['content']
    if system_message != "":
        formatted_messages += f"<|start_header_id|>system<|end_header_id|>"
        formatted_messages += f"{system_message}"
        formatted_messages += """

Reminder:
- Function calls MUST follow the specified format, start with <function= and end with </function>
- Required parameters MUST be specified
- Only call one function at a time
- Put the entire function call reply on one line
- Respond with something after the function call is complete"""
        formatted_messages += "<|eot_id|>"
    for index, item in enumerate(messages):
        role = item['role']
        if role == 'tool':
            role = 'ipython'
        if role == 'system':
            continue
        formatted_messages += f"<|start_header_id|>{role}<|end_header_id|>"
        if 'tool_calls' in item:
            for tool_call in item['tool_calls']:
                formatted_messages += "\n\n" + serialize_functionary31_call(tool_call['function']['name'], tool_call['function']['arguments'])
                formatted_messages += "<|eom_id|>"
        content = item['content'].strip()
        if role == 'ipython':
            formatted_messages += "\n\n"
            if content == "":
                formatted_messages += "NO RESULTS"
        formatted_messages += content
        formatted_messages += "<|eot_id|>"
    formatted_messages += f"<|start_header_id|>assistant<|end_header_id|>"
    return formatted_messages

def template_llama(self,messages):
    formatted_messages = f"<s>[INST]"
    if self.system_message != "":
        formatted_messages += f"<<SYS>>{self.system_message}<</SYS>>"
    self.terminator = "</s>"
    for index, item in enumerate(messages):
        if "role" in item:
            role = item['role']
        else:
            role = 'user'
        if "content" not in item:
            continue
        content = item['content']
        if role == 'user':
            formatted_messages += f"{content}[/INST] "
        elif role == 'hint':
            formatted_messages += f"Hint: {content}[/INST] "
        elif role == 'function':
            formatted_messages += f"Output: {content}[/INST] "
        elif role == 'assistant' and self.env["chat.reply"] == "true":
            formatted_messages += f"{content}</s><s>[INST]"
    return formatted_messages

def create_chat_completion(self, **kwargs):
    messages = kwargs.pop('messages')
    tools = kwargs.pop('tools')
    prompt = messages_to_prompt(self, messages, tools)
    return response_to_message(self, create_completion(self.llama_instance, prompt=prompt, **kwargs))


def create_completion(
        self,
        prompt: Union[str, List[int]],
        suffix: Optional[str] = None,
        max_tokens: Optional[int] = 16,
        temperature: float = 0.8,
        top_p: float = 0.95,
        min_p: float = 0.05,
        typical_p: float = 1.0,
        logprobs: Optional[int] = None,
        echo: bool = False,
        stop: Optional[Union[str, List[str]]] = [],
        frequency_penalty: float = 0.0,
        presence_penalty: float = 0.0,
        repeat_penalty: float = 1.0,
        top_k: int = 40,
        stream: bool = False,
        seed: Optional[int] = None,
        tfs_z: float = 1.0,
        mirostat_mode: int = 0,
        mirostat_tau: float = 5.0,
        mirostat_eta: float = 0.1,
        model: Optional[str] = None,
        stopping_criteria: Optional[StoppingCriteriaList] = None,
        logits_processor: Optional[LogitsProcessorList] = None,
        grammar: Optional[LlamaGrammar] = None,
        logit_bias: Optional[Dict[str, float]] = None,
    ) -> Union[
        Iterator[CreateCompletionResponse], Iterator[CreateCompletionStreamResponse]
    ]:

        prompt_tokens = self.tokenize(
            prompt.encode("utf-8"),
            add_bos=False,
            special=True
        )

        for token in self.generate(
            prompt_tokens,
            top_k=top_k,
            top_p=top_p,
            min_p=min_p,
            typical_p=typical_p,
            temp=temperature,
            tfs_z=tfs_z,
            mirostat_mode=mirostat_mode,
            mirostat_tau=mirostat_tau,
            mirostat_eta=mirostat_eta,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty,
            repeat_penalty=repeat_penalty,
            stopping_criteria=stopping_criteria,
            logits_processor=logits_processor,
            grammar=grammar,
        ):
            
            if llama_cpp.llama_token_is_eog(self._model.model, token):
                break
            text = self.detokenize([token], special=True).decode("utf-8")
            yield text