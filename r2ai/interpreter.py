import builtins
import re
import os
import sys
import traceback
import json
import platform
import getpass
import tokentrim

from rich.rule import Rule
from signal import signal, SIGINT

from .large import Large
from .utils import merge_deltas
from .message_block import MessageBlock
from .code_block import CodeBlock
from .backend import kobaldcpp
from .backend import openapi

from .models import get_hf_llm, new_get_hf_llm, get_default_model
from .voice import tts
from .const import R2AI_HOMEDIR
from . import auto, LOGGER, logging
from .web import stop_http_server, server_running

try:
    from openai import OpenAI, OpenAIError
    have_openai = True
except Exception:
    have_openai = False
    pass

try:
    from anthropic import Anthropic
    have_anthropic = True
except Exception:
    have_anthropic = False
    pass

try:
    from groq import Groq
    have_groq = True
except Exception:
    have_groq = False
    pass

try:
    import google.generativeai as google
    google.configure(api_key=os.environ['GOOGLE_API_KEY'])
    have_google = True
except Exception as e:
    have_google = False
    pass

file_dir = os.path.dirname(__file__)
sys.path.append(file_dir)
import index

r2clippy = False
have_rlang = False
try:
    import r2lang
    have_rlang = True
    print = r2lang.print
    r2clippy = True
except Exception:
    pass

Ginterrupted = False
def signal_handler(sig, frame):
    global Ginterrupted
    if Ginterrupted:
        stop_http_server(force=True) # kill if in background
        sys.exit(0) # throws exception
    Ginterrupted = True
    print("^C 0", file=sys.stderr)
    stop_http_server(force=False)
signal(SIGINT, signal_handler)

def exception_handler(self, sig, frame):
    global Ginterrupted
    traceback.print_exc()
    if Ginterrupted:
        sys.exit(0) # throws exception
    Ginterrupted = True
    print("^C 1", file=sys.stderr)
# sys.excepthook = exception_handler

def incodeblock(msg):
  return "content" in msg and msg["content"].count("```") % 2 == 1

def r2eval(m):
    if "$(" in m and have_rlang:
        def evaluate_expression(match):
            expression = match.group(1)
            try:
                result = r2lang.cmd(expression)
                return result
            except Exception as e:
                return f"Error: {e}"
        return re.sub(r'\$\((.*?)\)', evaluate_expression, m)
    return m

from utils import syscmdstr

def ddg(m):
    print("[R2AI] Crawling the web with ddg and curl+sed")
    m = m.replace("'", "")
    res = syscmdstr(f"cd examples; ./scrap-ddgweb.sh '{m}'")
    return f"Considering:\n```{res}\n```\n"

# move all this logic into r2ai/templates.py or r2ai/chat.py (chat_templates.py?)
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
    self.terminator = "Question:"
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
    formatted_messages = f"<|begin_of_text|>"
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

class Interpreter:
    def __init__(self):
        self.logger = LOGGER
        self.mistral = None
        self.messages = []
        self.terminator = "</s>" ## taken from the model using the llama api
        self.api_key = None # openai?
        self.print = None
        self.auto_run = False
        self.model = get_default_model()
        self.last_model = ""
        self.env = {}
        self.openai_client = None
        self.anthropic_client = None
        self.groq_client = None
        self.google_client = None
        self.google_chat = None
        self.bedrock_client = None
        self.api_base = "https://api.openai.com/v1" # Default openai base url
        self.system_message = ""
        self.env["llm.model"] = self.model ## TODO: dup. must get rid of self.model
        self.env["llm.gpu"] = "true"
        self.env["llm.window"] = "32768" # "4096" # context_window
        self.env["llm.maxtokens"] = "4096" # "1750"
        self.env["llm.maxmsglen"] = "8096" # "1750"
        self.env["llm.temperature"] = "0.002"
        self.env["llm.repeat_penalty"] = "1.0"
        self.env["llm.top_p"] = "0.95"
        self.env["llm.top_k"] = "50"
        self.env["user.name"] = "" # TODO auto fill?
        self.env["user.os"] = ""
        self.env["user.arch"] = ""
        self.env["user.cwd"] = ""
        self.env["user.editor"] = ""
        self.env["user.plugins"] = f"{R2AI_HOMEDIR}/plugins"
        self.env["voice.lang"] = "en"
        self.env["voice.model"] = "base"
        self.env["data.use"] = "false"
        self.env["data.path"] = f"{R2AI_HOMEDIR}/doc/data"
        self.env["data.local"] = "false"
        self.env["data.wikit"] = "false"
        self.env["data.ddg"] = "false"
        self.env["data.mastodon"] = "false"
        self.env["data.vectordb"] = "false"
        self.env["data.hist"] = "false"
        self.env["key.mastodon"] = ""
        self.env["key.openai"] = ""
        self.env["http.port"] = "8080"
        self.env["http.tabby"] = "false"
        self.env["http.path"] = ""
        self.env["http.verbose"] = "true" # not used yet
        self.env["http.chatctx"] = "false"
        if have_rlang:
            self.env["chat.live"] = "false"
        else:
            self.env["chat.live"] = "true"
        # self.env["chat.model"] = "" # TODO
        self.env["chat.trim"] = "false"
        self.env["chat.voice"] = "false"
        self.env["chat.bubble"] = "false"
        self.env["chat.reply"] = "false"
        self.env["chat.code"] = "true"

        # No active block to start
        # (blocks are visual representation of messages on the terminal)
        self.active_block = None

        # Note: While Open Interpreter can use Llama, we will prioritize gpt-4.
        # gpt-4 is faster, smarter, can call functions, and is all-around easier to use.
        # This makes gpt-4 better aligned with Open Interpreters priority to be easy to use.
        self.llama_instance = None
        self.large = Large(self)

    def get_info_for_system_message(self):
        """Gets relevent information for the system message."""
        info = ""
        # Add user info
        getpass.getuser()
        os.getcwd()
        platform.system()
        # info += f"[User Info]\nName: {username}\nCWD: {current_working_directory}\nOS: {operating_system}"
        return info

    def reset(self):
        """Resets the interpreter."""
        self.messages = []

    def load(self, messages):
        self.messages = messages

    def save(self, f):
        json.dumps(self.messages, f, indent=2)

    def handle_undo(self, arguments):
        """Remove all messages after the most recent user entry (and the entry itself).
        Therefore user can jump back to the latest point of conversation.
        Also gives a visual representation of the messages removed."""
        if len(self.messages) == 0:
            return
        # Find the index of the last 'role': 'user' entry
        last_user_index = None
        for i, message in enumerate(self.messages):
            if message.get('role') == 'user':
                last_user_index = i
        removed_messages = []
        # Remove all messages after the last 'role': 'user'
        if last_user_index is not None:
            removed_messages = self.messages[last_user_index:]
            self.messages = self.messages[:last_user_index]

        # Print out a preview of what messages were removed.
        for message in removed_messages:
            if message.get("content"):
                print(f"**Removed message:** `\"{message['content'][:30]}...\"`")
            elif 'function_call' in message:
                print(f"**Removed codeblock**") # TODO: Could add preview of code removed here.

    # reimplement using nltk or index.match
    def keywords_ai(self, text):
        # kws = self.keywords_ai("who is the author of radare?") => "author,radare2"
        words = []
        mmname = "TheBloke/Mistral-7B-Instruct-v0.2-GGUF"
        ctxwindow = int(self.env["llm.window"])
        mm = new_get_hf_llm(self, mmname, False, ctxwindow)
        msg = f"Considering the sentence \"{text}\" as input, Take the KEYWORDS or combination of TWO words from the given text and respond ONLY a comma separated list of the most relevant words. DO NOT introduce your response, ONLY show the words"
        msg = f"Take \"{text}\" as input, and extract the keywords and combination of keywords to make a search online, the output must be a comma separated list" #Take the KEYWORDS or combination of TWO words from the given text and respond ONLY a comma separated list of the most relevant words. DO NOT introduce your response, ONLY show the words"
        response = mm(msg, stream=False, temperature=0.1, stop="</s>", max_tokens=1750)
        self.logger.debug(response)
        text0 = response["choices"][0]["text"]
        text0 = text0.replace('"', ",")
        if text0.startswith("."):
            text0 = text0[1:].strip()
        try:
            text0 = text0.split(":")[1].strip()
        except Exception:
            pass
        # print(text0)
        mm = None
        return [word.strip() for word in text0.split(',')]

    def chat(self, message=None):
        global print
        global Ginterrupted

        if self.print is not None:
            print = self.print

        if self.last_model != self.model:
#            self.llama_instance = None
            self.last_model = self.model

        if not message and self.env["chat.code"] == "true":
            self.end_active_block()
            self.logger.error("Missing message")
            return

        if self.env["data.use"] == "true":
            use_hist = self.env["data.hist"] == "true"
            use_wikit = self.env["data.wikit"] == "true"
            use_mastodon = self.env["data.mastodon"] == "true"
            use_vectordb = self.env["data.vectordb"] == "true"
            use_debug = LOGGER.level == logging.DEBUG
            datadir = None
            keywords = None
            if use_mastodon:
                keywords = self.keywords_ai(message)
            if self.env["data.local"] == "true":
                datadir = self.env["data.path"]
            if self.env["data.ddg"] == "true":
                results = ddg(message)
                if use_vectordb:
                    index.memorize(message, results)
                else:
                    self.messages.append({"role": "hint", "content": results})
            matches = index.match(message, keywords, datadir, use_hist, use_mastodon, use_debug, use_wikit, use_vectordb)
            if not matches:
                matches = []

            if len(matches) > 0:
                for m in matches:
                    self.logger.debug("HINT: " + m)
                    self.messages.append({"role": "hint", "content": r2eval(m)})

        self.logger.debug(message)

        # print(message)
        # Local model
        if (
            not self.model.startswith("openai:") and
            not self.model.startswith("openapi:") and
            not self.model.startswith("kobaldcpp") and
            not self.model.startswith("bedrock:") and
            self.llama_instance is None
        ):
            self.logger = LOGGER.getChild(f"local:{self.model}")
            # Find or install Code-Llama
            try:
                ctxwindow = int(self.env["llm.window"])
                debug_mode = False # maybe true when debuglevel=2 ?
                self.llama_instance = new_get_hf_llm(self, self.model, debug_mode, ctxwindow)
                if self.llama_instance is None:
                    self.logger.error("Cannot find model " + self.model)
                    return
            except Exception:
                traceback.print_exc()

        # If it was, we respond non-interactively
        self.messages.append({"role": "user", "content": message})
        try:
            self.respond()
            self.clear_hints()
        except Exception:
            if Ginterrupted:
                Ginterrupted = False
            else:
                traceback.print_exc()
        self.end_active_block()

    def end_active_block(self):
        # if self.env["chat.code"] == "false":
        # return
        if self.active_block:
            self.active_block.end()
            self.active_block = None

    def environment(self):
        kvs = ""
        if self.env["user.name"] != "":
            kvs += "Name: " + self.env["user.name"] + "\n"
        if self.env["user.os"] != "":
            kvs += "OS: " + self.env["user.os"] + "\n"
        if self.env["user.cwd"] != "":
            kvs += "CWD: " + self.env["user.cwd"] + "\n"
        if self.env["user.editor"] != "":
            kvs += "EDITOR: " + self.env["user.editor"] + "\n"
        if self.env["user.arch"] != "":
            kvs += "ARCH: " + self.env["user.arch"] + "\n"
        # info += f"[User Info]\nName: {username}\nCWD: {current_working_directory}\nOS: {operating_system}"
        if kvs != "":
            return "[User Info]\n" + kvs
        return ""

    def clear_hints(self):
        res = []
        for msg in self.messages:
            if "role" in msg and msg["role"] != "hint":
                res.append(msg)
        self.messages = res

    def respond(self):
        global Ginterrupted
        self.logger = LOGGER.getChild(self.model.split(":")[0])
        maxtokens = int(self.env["llm.maxtokens"])
        # Add relevant info to system_message
        # (e.g. current working directory, username, os, etc.)
        info = self.get_info_for_system_message()

        # This is hacky, as we should have a different (minified) prompt for CodeLLama,
        # but for now, to make the prompt shorter and remove "run_code" references, just get the first 2 lines:
        self.system_message = "\n".join(self.system_message.split("\n")[:2])
        # self.system_message += "\nOnly do what the user asks you to do, then ask what they'd like to do next."

        system_message = self.system_message + "\n\n" + info
        system_message += self.environment()

        if self.env["chat.trim"] == "true":
            ## this stupid function is slow as hell and doesn not provides much goodies
            ## just ignore it by default
            messages = tokentrim.trim(self.messages, max_tokens=maxtokens, system_message=system_message)
        else:
            messages = self.large.compress_messages(self.messages)

            self.logger.debug(messages)

        # builtins.print(prompt)
        response = None
        if self.auto_run:
            response = auto.chat(self)
            return

        elif self.model.startswith("kobaldcpp"):
            if self.system_message != "":
                message = f"Context:\n```\n{self.system_message}\n```\n"
            else:
                message = ""
            #f"{Your name is r2ai, an assistant for radare2. User will ask about actions and you must respond with the radare2 command associated or the answer to the question. Be precise and concise when answering"
            for m in messages:
                role = m["role"]
                content = m["content"]
                if role == "user":
                    message += f"User: {content}\n"
                elif role == "assistant":
                    message += f"AI: {content}\n"
            response = ""
            if ":" in self.model:
                uri = self.model.split(":")[1:]
                response = kobaldcpp.chat(message, ":".join(uri))
            else:
                response = kobaldcpp.chat(message)
            if "content" in self.messages[-1]:
                last_message = self.messages[-1]["content"]
            if self.env["chat.reply"] == "true":
                self.messages.append({"role": "assistant", "content": response})
            print(response)
            return

        elif self.model.startswith("openai:") or self.model.startswith("openapi:"):
            # [
            #  {"role": "system", "content": "You are a poetic assistant, be creative."},
            #  {"role": "user", "content": "Compose a poem that explains the concept of recursion in programming."}
            # ]
            if self.model.startswith("openapi:"):
                uri = self.model.split(":", 3)[1:]
                if len(uri) > 2:
                    self.api_base = ":".join(uri[:-1])
                    openai_model = uri[-1]
            else:
                openai_model = self.model.rsplit(":")[-1]
            self.api_key = syscmdstr('cat ~/.r2ai.openai-key').strip();
            if have_openai:
                # https://platform.openai.com/docs/assistants/overview
                if self.openai_client is None:
                    self.openai_client = OpenAI(base_url=self.api_base)
                if self.system_message != "":
                    self.messages.append({"role": "system", "content": self.system_message})
                try:
                    completion = self.openai_client.chat.completions.create(
                        # TODO: instructions=self.system_message # instead of passing it in the query
                        model=openai_model,
                        max_tokens=maxtokens,
                        temperature=float(self.env["llm.temperature"]),
                        messages=self.messages,
                        extra_headers={
                            "HTTP-Referer": "https://rada.re", # openrouter specific: Optional, for including your app on openrouter.ai rankings.
                            "X-Title": "radare2", # openrouter specific: Optional. Shows in rankings on openrouter.ai.
                        }
                    )
                except OpenAIError as e:
                    self.logger.error("OpenAIError[%s]: %s", e.body['code'], e.body['message'])
                    return
                except Exception as e:
                    self.logger.error("Exception %s", e)
                    return
                response = completion.choices[0].message.content
                if "content" in self.messages[-1]:
                    last_message = self.messages[-1]["content"]
                if self.env["chat.reply"] == "true":
                    self.messages.append({"role": "assistant", "content": response})
                print(response)
            else:
                self.logger.warn("OpenAi python not found. Falling back to requests library")
                response = openapi.chat(self.messages, self.api_base, openai_model, self.api_key) 
                if "content" in self.messages[-1]:
                    last_message = self.messages[-1]["content"]
                if self.env["chat.reply"] == "true":
                    self.messages.append({"role": "assistant", "content": response})
                print(response)
                self.logger.warn("For a better experience install openai python")
                self.load.warn("pip install -U openai")
                self.logger.warn("export OPENAI_API_KEY=...")
            return

        elif self.model.startswith('anthropic:'):
            anthropic_model = self.model[10:]
            messages = []
            lastrole = ""
            for m in self.messages:
                if lastrole != "":
                    if lastrole == "user" and m["role"] == "user":
                        m2 = {"role": "assistant", "content": "."}
                        messages.append(m2)
                lastrole = m["role"]
                if m["role"] == "system":
                    system_message = m["content"]
                else:
                    messages.append(m)
            if have_anthropic:
                if self.anthropic_client is None:
                    self.anthropic_client = Anthropic()
                completion = self.anthropic_client.messages.create(
                    system=system_message,
                    model=anthropic_model,
                    max_tokens=maxtokens,
                    temperature=float(self.env["llm.temperature"]),
                    repeat_penalty=float(self.env["llm.repeat_penalty"]),
                    messages=messages
                )
                if self.env["chat.reply"] == "true":
                    self.messages.append({"role": "assistant", "content": completion.content})
                print(completion.content[0].text)
                return
            else:
                self.logger.error("pip install -U anthropic")
                self.logger.error("export ANTHROPIC_API_KEY=...")
                return

        elif self.model.startswith("bedrock:"):
            import boto3
            bedrock_model = self.model.split(":")[1] + ":0"
            self.bedrock_client = boto3.client("bedrock-runtime")
            request = {
                "anthropic_version": "bedrock-2023-05-31",
                "temperature": float(self.env["llm.temperature"]),
                "repeat_penalty": float(self.env["llm.repeat_penalty"]),
                "max_tokens": maxtokens,
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "text", "text": m["content"]} for m in self.messages],
                    }
                ],
            }
            response = self.bedrock_client.invoke_model(
                modelId=bedrock_model,
                body=json.dumps(request)
            )
            model_response = json.loads(response["body"].read())
            response = model_response["content"][0]["text"]

        elif self.model.startswith('groq:'):
            if have_groq:
                self.groq_client = Groq()
                completion = self.groq_client.completions.create(
                    model=self.model[5:],
                    max_tokens=maxtokens,
                    temperature=float(self.env["llm.temperature"]),
                    repeat_penalty=float(self.env["llm.repeat_penalty"]),
                    messages=self.messages
                )
                if self.env["chat.reply"] == "true":
                    self.messages.append({"role": "assistant", "content": completion.content})
                    print(completion.content)

        elif self.model.startswith('google:'):
            if have_google:
                if not self.google_client:
                    self.google_client = google.GenerativeModel(self.model[7:])
                if not self.google_chat:
                    self.google_chat = self.google_client.start_chat()
                completion = self.google_chat.send_message(
                    self.messages[-1]["content"],
                    generation_config={
                        "max_output_tokens": maxtokens,
                        "temperature": float(self.env["llm.temperature"]),
                        "repeat_penalty": float(self.env["llm.repeat_penalty"])
                    }
                )
                if self.env["chat.reply"] == "true":
                    self.messages.append({"role": "assistant", "content": completion.text})
                print(completion.text)
            return

        else:
            # non-openai aka local-llama model
            if self.llama_instance == None:
                self.logger.critical("Llama is not instantiated")
                return
            try:
                # Convert messages to prompt
                # (This only works if the first message is the only system message)
                prompt = messages_to_prompt(self, messages)
                if type(self.terminator).__name__ == "list":
                    terminator = self.terminator
                else:
                    terminator = [self.terminator]
                response = self.llama_instance(
                    prompt,
                    stream=True,
                    temperature=float(self.env["llm.temperature"]),
                    repeat_penalty=float(self.env["llm.repeat_penalty"]),
                    top_p=float(self.env["llm.top_p"]),
                    top_k=int(self.env["llm.top_k"]),
                    stop=terminator,
                    max_tokens=maxtokens
                )
            except Exception as err:
                print(Exception, err)
                if Ginterrupted:
                    Ginterrupted = False
                    return

        if response is None:
            print("No response")
            ctxwindow = int(self.env["llm.window"])
            self.llama_instance = new_get_hf_llm(self, self.model, False, ctxwindow)
            return
        # Initialize message, function call trackers, and active block
        self.messages.append({})
        in_function_call = False
        self.active_block = MessageBlock()
        for chunk in response:
            if Ginterrupted:
                Ginterrupted = False
                break
            if "content" not in messages[-1]:
                # This is the first chunk. We'll need to capitalize it, because our prompt ends in a ", "
                chunk["choices"][0]["text"] = chunk["choices"][0]["text"].capitalize()
                # We'll also need to add "role: assistant", CodeLlama will not generate this
                messages[-1]["role"] = "assistant"
            delta = {"content": chunk["choices"][0]["text"]}
            # Accumulate deltas into the last message in messages
            self.messages[-1] = merge_deltas(self.messages[-1], delta)
            if self.env["chat.live"] != "true":
                continue
            flushed = False
            if self.env["chat.code"] == "true":
                if incodeblock(self.messages[-1]):
                    if in_function_call == False:
                        in_function_call = True
                        self.active_block.update_from_message(self.messages[-1])
                        self.end_active_block()
                        # flushed = True
                        self.active_block = CodeBlock()
                else:
                    if in_function_call == True:
                        in_function_call = False
                        self.end_active_block()
                        flushed = True
                        self.active_block = MessageBlock()
            if self.env["chat.live"] == "true": # and self.env["chat.code"] == "true":
                self.active_block.update_from_message(self.messages[-1])
                if flushed:
                    self.messages[-1]["content"] = ""
            continue # end of for loop
        self.end_active_block()
        self.active_block = None
        output_text = ""
        if len(self.messages) > 0 and "content" in self.messages[-1]:
            output_text = self.messages[-1]["content"].strip()
        if self.env["chat.reply"] == "true":
            self.messages.append({"role": "assistant", "content": output_text})
        if self.env["chat.voice"] == "true":
            tts("(assistant)", output_text, self.env["voice.lang"])
        elif self.env["chat.live"] != "true":
            try:
                r2lang.print(output_text)
            except Exception:
                print(output_text)
            # print(str(self.messages))
