import builtins
from .large import Large
from .utils import merge_deltas
from .message_block import MessageBlock
from .code_block import CodeBlock
from .backend import kobaldcpp

from .models import get_hf_llm, new_get_hf_llm, get_default_model
from .voice import tts
from .const import R2AI_HOMEDIR
from . import auto
import os

try:
  from openai import OpenAI
  have_openai = True
except:
  have_openai = False
  pass

try:
  from anthropic import Anthropic
  have_anthropic = True
except:
  have_anthropic = False
  pass

try:
  from groq import Groq
  have_groq = True
except:
  have_groq = False
  pass

try:
  import google.generativeai as google
  google.configure(api_key=os.environ['GOOGLE_API_KEY'])
  have_google = True
except Exception as e:
  have_google = False
  pass

import re
import os
import traceback
import json
import platform
import getpass
from rich.rule import Rule
from signal import signal, SIGINT
import sys

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
except:
	pass

Ginterrupted = False
def signal_handler(sig, frame):
	global Ginterrupted
	if Ginterrupted:
	    sys.exit(0) # throws exception
	Ginterrupted = True
	print("^C", file=sys.stderr)
signal(SIGINT, signal_handler)

def exception_handler(self, sig, frame):
	global Ginterrupted
	if Ginterrupted:
	    sys.exit(0) # throws exception
	Ginterrupted = True
	print("^C", file=sys.stderr)
sys.excepthook = exception_handler

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
  elif "Phi" in lowermodel:
    formatted_messages = template_phi3(self, messages)
  elif "coder" in lowermodel:
    formatted_messages = template_alpaca(self, messages)
  elif "deepseek" in lowermodel:
    formatted_messages = template_alpaca(self, messages)
  elif "uncensor" in lowermodel:
#    formatted_messages = template_gpt4all(self, messages)
#    formatted_messages = template_alpaca(self, messages)
    formatted_messages = template_uncensored(self, messages)
#    formatted_messages = template_gpt4all(self, messages)
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
  elif "llama-3" in lowermodel:
    formatted_messages = template_llama3(self, messages)
  else:
    formatted_messages = template_llama(self, messages)

  if self.env["debug"] == "true":
    builtins.print(formatted_messages)
  return formatted_messages

def template_gemma(self,messages):
  self.terminator = ["<end_of_turn>"] #, "SneakyThrows", "\n"]
  formatted_messages = ""
  try:
    system_prompt = self.system_message
    if system_prompt != "":
      formatted_messages += f"<start_of_turn>model\n{system_prompt}<end_of_turn>"
    for index, item in enumerate(messages):
      role = item['role']
      if role == "assistant":
        role = "user"
      content = item['content'].strip()
      formatted_messages += f"<start_of_turn>{role}\n{content}<end_of_turn>\n"
    formatted_messages += f"<start_of_turn>model\n"
    #print("```\n" + formatted_messages + "\n```")
  except:
    traceback.print_exc()
  return formatted_messages

def template_q4im(self,messages):
  self.terminator = "<|im_end|>"
  formatted_messages = ""
  try:
    system_prompt = messages[0]['content'].strip()
    if system_prompt != "":
#      formatted_messages += "\{\"text\":\"{"+system_prompt+"}\"\}"
      formatted_messages += f"<|im_start|>assistant {system_prompt}<|im_end|>"
 #formatted_messages += f"<|im_start|>system\n{system_prompt}<|im_end|>"
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
  except:
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
  except:
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
#          formatted_messages += f"### Assistant: {content}\n"
          formatted_messages += f"{content}\n"
    formatted_messages += f"### Assistant:"
    # print("```" + formatted_messages + "```")
  except:
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
#   TheBloke/TinyLlama-1.1B-Chat-v0.3-GGUF
#<|></SENT>
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
      formatted_messages += f"<|start_header_id|>{self.system_message}<|end_header_id|>"
  self.terminator = "<|end_header_id|>"
  self.terminator = "<|eot_id|>"
  self.terminator = "assistant"
  for index, item in enumerate(messages):
      if "role" in item:
          role = item['role']
      else:
          role = 'user'
      if "content" not in item:
          continue
      content = item['content']
      if role == 'user':
          formatted_messages += f"{content}<|eot_id|>"
      elif role == 'hint':
          formatted_messages += f"Hint: {content}<|eot_id|> "
      elif role == 'function':
          formatted_messages += f"Output: {content}<|eot_id|> "
      elif role == 'assistant' and self.env["chat.reply"] == "true":
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
    self.api_base = None # Will set it to whatever OpenAI wants
    self.system_message = ""
    self.env["debug"] = "false"
    self.env["llm.model"] = self.model ## TODO: dup. must get rid of self.model
    self.env["llm.gpu"] = "true"
    self.env["llm.window"] = "8096" # "4096" # context_window
    self.env["llm.maxtokens"] = "4096" # "1750"
    self.env["llm.maxmsglen"] = "8096" # "1750"
    self.env["llm.temperature"] = "0.002"
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
    self.env["data.mastodon"] = "false"
    self.env["data.vectordb"] = "false"
    self.env["data.hist"] = "false"
    self.env["key.mastodon"] = ""
    self.env["key.openai"] = ""
    self.env["http.port"] = "8080"
    self.env["http.path"] = ""
    self.env["http.chatctx"] = "false"
    if have_rlang:
      self.env["chat.live"] = "false"
    else:
      self.env["chat.live"] = "true"
#self.env["chat.model"] = "" # TODO
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

  def get_info_for_system_message(self):
    """
    Gets relevent information for the system message.
    """

    info = ""

    # Add user info
    getpass.getuser()
    os.getcwd()
    platform.system()
#   info += f"[User Info]\nName: {username}\nCWD: {current_working_directory}\nOS: {operating_system}"

    return info

  def reset(self):
    """
    Resets the interpreter.
    """
    self.messages = []

  def load(self, messages):
    self.messages = messages

  def save(self, f):
    json.dumps(self.messages, f, indent=2)

  def handle_undo(self, arguments):
    # Removes all messages after the most recent user entry (and the entry itself).
    # Therefore user can jump back to the latest point of conversation.
    # Also gives a visual representation of the messages removed.

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
      if 'content' in message and message['content'] != None:
        print(f"**Removed message:** `\"{message['content'][:30]}...\"`")
      elif 'function_call' in message:
        print(f"**Removed codeblock**") # TODO: Could add preview of code removed here.

  def keywords_ai(self, text):
    # kws = self.keywords_ai("who is the author of radare?") => "author,radare2"
    words = []
    mmname = "TheBloke/Mistral-7B-Instruct-v0.2-GGUF"
    ctxwindow = int(self.env["llm.window"])
    mm = new_get_hf_llm(self, mmname, False, ctxwindow)
    msg = f"Considering the sentence \"{text}\" as input, Take the KEYWORDS or combination of TWO words from the given text and respond ONLY a comma separated list of the most relevant words. DO NOT introduce your response, ONLY show the words"
    msg = f"Take \"{text}\" as input, and extract the keywords and combination of keywords to make a search online, the output must be a comma separated list" #Take the KEYWORDS or combination of TWO words from the given text and respond ONLY a comma separated list of the most relevant words. DO NOT introduce your response, ONLY show the words"
    response = mm(msg, stream=False, temperature=0.1, stop="</s>", max_tokens=1750)
    if self.env["debug"] == "true":
      print("KWSPLITRESPONSE", response)
    text0 = response["choices"][0]["text"]
    text0 = text0.replace('"', ",")
    if text0.startswith("."):
      text0 = text0[1:].strip()
    try:
      text0 = text0.split(":")[1].strip()
    except:
      pass
    # print(text0)
    mm = None
    return [word.strip() for word in text0.split(',')]

  def chat(self, message=None):
    global print
    global Ginterrupted
    if self.print != None:
      print = self.print
    if self.last_model != self.model:
      self.llama_instance = None
      self.last_model = self.model
    if not message and self["chat.code"] == "true":
      self.end_active_block()
      print("Missing message")
      return
    if self.env["data.use"] == "true":
      use_hist = self.env["data.hist"] == "true"
      use_wikit = self.env["data.wikit"] == "true"
      use_mastodon = self.env["data.mastodon"] == "true"
      use_vectordb = self.env["data.vectordb"] == "true"
      use_debug = self.env["debug"] == "true"
      datadir = None
      keywords = None
      if use_mastodon:
        keywords = self.keywords_ai(message)
      if self.env["data.local"] == "true":
        datadir = self.env["data.path"]
      matches = index.match(message, keywords, datadir, use_hist, use_mastodon, use_debug, use_wikit, use_vectordb)
      if matches == None:
        matches = []
      if len(matches) > 0:
        for m in matches:
          if self.env["debug"] == "true":
            print("HINT: " + m)
          self.messages.append({"role": "hint", "content": r2eval(m)})
    if self.env["debug"] == "true":
      print(message)
#    print(message)
    # Code-Llama
    if not self.model.startswith("openai:") and not self.model.startswith("kobaldcpp") and self.llama_instance == None:
      # Find or install Code-Llama
      try:
        ctxwindow = int(self.env["llm.window"])
        debug_mode = False # maybe true when debuglevel=2 ?
        self.llama_instance = new_get_hf_llm(self, self.model, debug_mode, ctxwindow)
        if self.llama_instance == None:
          builtins.print("Cannot find the model")
          return
      except:
        traceback.print_exc()

    # If it was, we respond non-interactively
    self.messages.append({"role": "user", "content": message})
    try:
        self.respond()
        self.clear_hints()
    except:
        if Ginterrupted:
            Ginterrupted = False
        else:
            traceback.print_exc()
    self.end_active_block()

  def end_active_block(self):
#    if self.env["chat.code"] == "false":
#      return
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

  def trimsource(self, msg):
    msg = msg.replace("public ", "")
    msg = re.sub(r'import.*\;', "", msg)
    msg = msg.replace("const ", "")
    msg = msg.replace("new ", "")
    msg = msg.replace("undefined", "0")
    msg = msg.replace("null", "0")
    msg = msg.replace("false", "0")
    msg = msg.replace("true", "1")
    msg = msg.replace("let ", "")
    msg = msg.replace("var ", "")
    msg = msg.replace("class ", "")
    msg = msg.replace("interface ", "")
    msg = msg.replace("function ", "fn ")
    msg = msg.replace("substring", "")
    msg = msg.replace("this.", "")
    msg = msg.replace("while (", "while(")
    msg = msg.replace("if (", "if(")
    msg = msg.replace("!== 0", "")
    msg = msg.replace("=== true", "")
    msg = msg.replace(" = ", "=")
    msg = msg.replace(" === ", "==")
    msg = msg.replace("\t", " ")
    msg = msg.replace("\n", "")
    msg = re.sub(r"/\*.*?\*/", '', msg, flags=re.DOTALL)
    # msg = re.sub(r"\n+", "\n", msg)
    msg = re.sub(r"\t+", ' ', msg)
    msg = re.sub(r"\s+", " ", msg)
    # msg = msg.replace(";", "")
    return msg.strip()

  def trimsource_ai(self, msg):
    words = []
    if self.mistral == None:
      mmname = "TheBloke/Mistral-7B-Instruct-v0.1-GGUF"
      mmname = "TheBloke/Mistral-7B-Instruct-v0.2-GGUF"
      ctxwindow = int(self.env["llm.window"])
      self.mistral = new_get_hf_llm(self, mmname, False, ctxwindow)
    # q = f"Rewrite this code into shorter pseudocode (less than 500 tokens). keep the comments and essential logic:\n```\n{msg}\n```\n"
    q = f"Rewrite this code into shorter pseudocode (less than 200 tokens). keep the relevant comments and essential logic:\n```\n{msg}\n```\n"
    response = self.mistral(q, stream=False, temperature=0.1, stop="</s>", max_tokens=4096)
    text0 = response["choices"][0]["text"]
    if "```" in text0:
      return text0.split("```")[1].strip()
    return text0.strip().replace("```", "")

  def compress_code_ai(self, code):
    piecesize = 1024 * 8 # mistral2 supports 32k vs 4096
    codelen = len(code)
    pieces = int(codelen / piecesize)
    if pieces < 1:
      pieces = 1
    plen = int(codelen / pieces)
    off = 0
    res = []
    for i in range(pieces):
      piece = i + 1
      print(f"Processing {piece} / {pieces} ...")
      if piece == pieces:
        r = self.trimsource_ai(code[off:])
      else:
        r = self.trimsource_ai(code[off:off+plen])
      res.append(r)
      off += plen
    return "\n".join(res)

  def compress_messages(self, messages):
    # TODO: implement a better logic in here asking the lm to summarize the context
    olen = 0
    msglen = 0
    for msg in messages:
      if self.env["chat.reply"] == "false":
        if msg["role"] != "user":
          continue
      if "content" in msg:
        amsg = msg["content"]
        olen += len(amsg)
        if len(amsg) > int(self.env["llm.maxmsglen"]):
          if "while" in amsg and "```" in amsg:
            que = re.search(r"^(.*?)```", amsg, re.DOTALL).group(0).replace("```", "")
            cod = re.search(r"```(.*?)$", amsg, re.DOTALL).group(0).replace("```", "")
            shortcode = cod
            while len(shortcode) > 4000:
              olen = len(shortcode)
              shortcode = self.compress_code_ai(shortcode)
              nlen = len(shortcode)
              print(f"Went from {olen} to {nlen}")
            msg["content"] = f"{que}\n```\n{shortcode}\n```\n"
          else:
            print(f"total length {msglen} (original length was {olen})")
        msglen += len(msg["content"])
    # print(f"total length {msglen} (original length was {olen})")
    # if msglen > 4096:
    #   ¡print("Query is too large.. you should consider triming old messages")
    return messages
  
  def respond(self):
    global Ginterrupted
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
      import tokentrim
      messages = tokentrim.trim(self.messages, max_tokens=maxtokens, system_message=system_message)
    else:
      messages = self.compress_messages(self.messages)

    if self.env["debug"] == "true":
      print(messages)

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
      response = kobaldcpp.chat(message)
      if "content" in self.messages[-1]:
        last_message = self.messages[-1]["content"]
      if self.env["chat.reply"] == "true":
        self.messages.append({"role": "assistant", "content": response})
      print(response)
      return
    elif self.model.startswith("openai:"):
      # [
      #  {"role": "system", "content": "You are a poetic assistant, be creative."},
      #  {"role": "user", "content": "Compose a poem that explains the concept of recursion in programming."}
      # ]
      openai_model = self.model[7:]
      if have_openai:
        # https://platform.openai.com/docs/assistants/overview
        if self.openai_client is None:
          self.openai_client = OpenAI()

        if self.system_message != "":
          self.messages.append({"role": "system", "content": self.system_message})

        completion = self.openai_client.chat.completions.create(
          # TODO: instructions=self.system_message # instead of passing it in the query
          model=openai_model,
          max_tokens=maxtokens,
          temperature=float(self.env["llm.temperature"]),
          messages=self.messages
        )
        response = completion.choices[0].message.content
        if "content" in self.messages[-1]:
          last_message = self.messages[-1]["content"]
        if self.env["chat.reply"] == "true":
          self.messages.append({"role": "assistant", "content": response})
        print(response)
        return
      else:
        print("pip install -U openai", file=sys.stderr)
        print("export OPENAI_API_KEY=...", file=sys.stderr)
        return
    elif self.model.startswith('anthropic:'):
      anthropic_model = self.model[10:]
      messages = []
      for m in self.messages:
        if m["role"] == "system":
          system_message = m["content"]
        else:
          messages.append(m["content"])

      if have_anthropic:
        if self.anthropic_client is None:
          self.anthropic_client = Anthropic()
        completion = self.anthropic_client.messages.create(
          model=anthropic_model,
          max_tokens=maxtokens,
          temperature=float(self.env["llm.temperature"]),
          messages=messages
        )

        if self.env["chat.reply"] == "true":
          self.messages.append({"role": "assistant", "content": completion.content})
          print(completion.content)
      else:
        print("pip install -U anthropic", file=sys.stderr)
        print("export ANTHROPIC_API_KEY=...", file=sys.stderr)
        return
    elif self.model.startswith('groq:'):
      if have_groq:
        self.groq_client = Groq()
        completion = self.groq_client.completions.create(
          model=self.model[5:],
          max_tokens=maxtokens,
          temperature=float(self.env["llm.temperature"]),
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
            "temperature": float(self.env["llm.temperature"])
          } 
        )
        if self.env["chat.reply"] == "true":
          self.messages.append({"role": "assistant", "content": completion.text})
        print(completion.text)
        return
    else:
      # non-openai aka local-llama model
      if self.llama_instance == None:
        print("Cannot find the model")
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
          stop=terminator,
          max_tokens=maxtokens
        )
      except Exception as err:
        print(Exception, err)
      except:
        if Ginterrupted:
          Ginterrupted = False
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
#            flushed = True
            self.active_block = CodeBlock()
        else:
          if in_function_call == True:
            in_function_call = False
            self.end_active_block()
            flushed = True
            self.active_block = MessageBlock()
#      else:
#        print(self.messages[-1])

      if self.env["chat.live"] == "true": # and self.env["chat.code"] == "true":
        self.active_block.update_from_message(self.messages[-1])
        if flushed:
          self.messages[-1]["content"] = ""
#     else:
#      print(self.messages[-1])
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
      except:
        print(output_text)
#        print(str(self.messages))
