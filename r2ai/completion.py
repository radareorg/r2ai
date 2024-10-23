import sys
import traceback
from . import LOGGER

def messages_to_prompt(self, messages):
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
    elif "llama-3" in lowermodel:
        formatted_messages = template_llama3(self, messages)
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
