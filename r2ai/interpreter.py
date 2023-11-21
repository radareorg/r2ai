import builtins
from .utils import merge_deltas
from .message_block import MessageBlock
from .code_block import CodeBlock
from .index import main_indexer
from .models import get_hf_llm, new_get_hf_llm, get_default_model
from .voice import tts
from .const import R2AI_HOMEDIR
try:
  from openai import OpenAI
  have_openai = True
except:
  have_openai = False
  pass


import re
import os
import traceback
import json
import platform
import getpass
from rich.rule import Rule
import signal
import sys

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
	print("^C")
sys.excepthook = signal_handler
signal.signal(signal.SIGINT, signal_handler)

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

def messages_to_prompt(self, messages):
  for message in messages:
    # Happens if it immediatly writes code
    if "role" not in message:
      message["role"] = "assistant"

  if "q4_0" in self.model.lower():
    formatted_messages = template_q4im(self, messages)
  elif "tief" in self.model.lower():
    formatted_messages = template_tiefighter(self, messages)
  elif "luna" in self.model.lower():
    formatted_messages = template_alpaca(self, messages)
  elif "uncensor" in self.model.lower():
#    formatted_messages = template_gpt4all(self, messages)
#    formatted_messages = template_alpaca(self, messages)
    formatted_messages = template_uncensored(self, messages)
#    formatted_messages = template_gpt4all(self, messages)
  elif "gpt4all" in self.model.lower():
    formatted_messages = template_gpt4all(self, messages)
  elif "falcon" in self.model.lower():
    formatted_messages = template_falcon(self, messages)
  elif "utopia" in self.model.lower():
    formatted_messages = template_alpaca(self, messages)
  elif "mistral" in self.model.lower():
    formatted_messages = template_mistral(self, messages)
  elif "python" in self.model.lower():
    print("codellama-python model is not working well yet")
    formatted_messages = template_llamapython(self, messages)
  elif "tinyllama" in self.model.lower():
    formatted_messages = template_tinyllama(self, messages)
  else:
    formatted_messages = template_llama(self, messages)

  if self.env["debug"] == "true":
    builtins.print(formatted_messages)
  return formatted_messages


def template_q4im(self,messages):
  self.terminator = "<|im_end|>"
  formatted_messages = ""
  try:
    system_prompt = messages[0]['content'].strip()
    if system_prompt != "":
#      formatted_messages += "\{\"text\":\"{"+system_prompt+"}\"\}"
      formatted_messages += f"<|im_start|>assistant {system_prompt}<|im_end|>"
      # formatted_messages = f"[STDIN] {system_prompt} [/STDIN]\n"
      # formatted_messages = f"/imagine prompt: {system_prompt}\n"
    for index, item in enumerate(messages[1:]):
        role = item['role']
        content = item['content'].strip()
        formatted_messages += f"<|im_start|>{content}<|im_end|>"
        formatted_messages += "\{\"text\":\"{"+content+"}\"\}"
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
        next
      content = item['content'].strip()
      if role == "user":
        msg += f"[INST]{content}[/INST]"
      elif role == "hint":
        msg += f"[INST]* {content}[/INST]"
      elif role == "assistant" and self.withresponse:
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
      elif role == "assistant" and self.withresponse:
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
      elif role == 'assistant' and self.withresponse:
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
      elif self.withresponse:
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
          next
      content = item['content']
      if content is None or content == "":
          next
      content = content.strip()
      if role == 'user':
          formatted_messages += f"[Instructions] {content} [/Instructions]\n"
      elif self.withresponse:
          formatted_messages += f"[Assistant] {content}\n"
#         formatted_messages += f"### Response:\n{content}\n"
  formatted_messages += f"[Assistant]"
  return formatted_messages

def template_alpaca(self, messages):
  self.terminator = "###"
  system_prompt = messages[0]['content'].strip()
  if system_prompt != "":
      formatted_messages = f"### Instruction:\n{system_prompt}\n"
  else:
      formatted_messages = ""
  # Loop starting from the first user message
  for index, item in enumerate(messages[1:]):
      role = item['role']
      if not 'content' in item:
          next
      content = item['content']
      if content is None or content == "":
          next
      content = content.strip()
      if role == 'user':
          formatted_messages += f"### Instruction:\n{content}\n"
      elif role == 'hint':
          formatted_messages += f"### Knowledge:\n{content}\n"
      elif self.withresponse:
          formatted_messages += f"### Assistant:\n{content}\n"
#         formatted_messages += f"### Response:\n{content}\n"
  formatted_messages += f"### Response: "
  return formatted_messages

def template_gpt4all(self,messages):
  self.terminator = "###"
  system_prompt = messages[0]['content'].strip()
  if system_prompt != "":
      formatted_messages = f"### Instruction: {system_prompt}\n"
  else:
      formatted_messages = ""
  # Loop starting from the first user message
  for index, item in enumerate(messages[1:]):
      role = item['role']
      content = item['content']
      if content is None or content == "":
          next
      content = content.strip()
      if role == 'user':
          formatted_messages += f"### User: {content}\n"
      elif self.withresponse:
          formatted_messages += f"### System: {content}\n"
  formatted_messages += f"### System: "
  return formatted_messages

def template_llama(self,messages):
  # Llama prompt template
  # Extracting the system prompt and initializing the formatted string with it.
  self.terminator = "</s>"
  system_prompt = messages[0]['content'].strip()
  if system_prompt != "":
      formatted_messages = f"<s>[INST]<<SYS>>{system_prompt}<</SYS>>"
  else:
      formatted_messages = f"<s>[INST]"
  # Loop starting from the first user message
  for index, item in enumerate(messages[1:]):
      if "role" in item:
          role = item['role']
      else:
          role = 'user'
      if "content" in item:
          content = item['content']
      else:
          continue
      if role == 'hint':
          role = 'assistant'
      if role == 'user':
          formatted_messages += f"{content}[/INST] "
      elif role == 'function':
          formatted_messages += f"Output: {content}[/INST] "
      elif role == 'assistant' and self.withresponse:
          formatted_messages += f"{content}</s><s>[INST]"
  # Remove the trailing '<s>[INST] ' from the final output
  if formatted_messages.endswith("<s>[INST]"):
      formatted_messages = formatted_messages[:-9]
  return formatted_messages

class Interpreter:
  def __init__(self):
    self.withresponse = False
    self.messages = []
    self.temperature = 0.002
    self.terminator = "</s>"
    self.api_key = None
    self.auto_run = False
    self.model = get_default_model()
    self.last_model = ""
    self.env = {}
    self.openai_client = None
    self.api_base = None # Will set it to whatever OpenAI wants
    self.context_window = 4096 # Make it configurable
    # self.max_tokens = 750 # For local models only
    self.max_tokens = 1750 # For local models only // make it configurable
    self.system_message = ""
    self.env["debug"] = "false"
    self.env["user.name"] = "" # TODO auto fill?
    self.env["user.os"] = ""
    self.env["user.arch"] = ""
    self.env["user.cwd"] = ""
    self.env["voice.lang"] = "en"
    self.env["voice.model"] = "base"
    self.env["data.use"] = "false"
    self.env["data.path"] = f"{R2AI_HOMEDIR}/doc/data"
    self.env["data.local"] = "false"
    self.env["data.hist"] = "false"
    self.env["data.mastodon"] = "false"
    self.env["key.mastodon"] = ""
    self.env["key.openai"] = ""
#    self.env["chat.temperature"] = "0.002" # TODO
    if have_rlang:
      self.env["chat.live"] = "false"
    else:
      self.env["chat.live"] = "true"
#self.env["chat.model"] = "" # TODO
    self.env["chat.trim"] = "false"
    self.env["chat.voice"] = "false"
    self.env["chat.bubble"] = "false"
    self.env["chat.reply"] = "true"

    # Get default system message
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, 'system_message.txt'), 'r') as f:
      self.system_message = f.read().strip()

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

  def systag(self, beg):
    lowermodel = self.model.lower()
    if "llama" in lowermodel:
      return "[INST]<<SYS>>" if beg else "<</SYS>>[/INST]"
    return "[INST]" if beg else "[/INST]\n"

  def chat(self, message=None):
    global Ginterrupted
    if self.last_model != self.model:
      self.llama_instance = None
      self.last_model = self.model
    if not message:
      self.end_active_block()
      print("Missing message")
      return
    if self.env["data.use"] == "true":
      hist = self.env["data.hist"] == "true"
      use_mastodon = self.env["data.mastodon"] == "true"
      use_debug = self.env["debug"] == "true"
      datadir = None
      if self.env["data.local"] == "true":
        datadir = self.env["data.path"]
      matches = main_indexer(message, datadir, hist, use_mastodon, use_debug)
      if len(matches) > 0:
        for m in matches:
          if self.env["debug"] == "true":
            print("HINT: " + m)
          self.messages.append({"role": "hint", "content": r2eval(m)})
    if self.env["debug"] == "true":
      print(message)
#    print(message)
    # Code-Llama
    if not self.model.startswith("openai:") and self.llama_instance == None:
      # Find or install Code-Llama
      try:
        debug_mode = self.env["debug"] == "true"
        self.llama_instance = new_get_hf_llm(self.model, debug_mode, self.context_window)
        if self.llama_instance == None:
          print("Cannot find the model")
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

  def compress_messages(self, messages):
    msglen = 0
    for msg in messages:
      if "content" in msg:
        msglen += len(msg["content"])
    if msglen > 8000:
      print("Query is too large.. you should consider triming old messages")
    return messages

  def respond(self):
    global Ginterrupted
    # Add relevant info to system_message
    # (e.g. current working directory, username, os, etc.)
    info = self.get_info_for_system_message()

    # This is hacky, as we should have a different (minified) prompt for CodeLLama,
    # but for now, to make the prompt shorter and remove "run_code" references, just get the first 2 lines:
    self.system_message = "\n".join(self.system_message.split("\n")[:2])
      # self.system_message += "\nOnly do what the user asks you to do, then ask what they'd like to do next."

    system_message = self.system_message + "\n\n" + info
    system_message += self.environment()

    if self.env["chat.trim"]:
      ## this stupid function is slow as hell and doesn not provides much goodies
      ## just ignore it by default
      import tokentrim
      messages = tokentrim.trim(self.messages,
          max_tokens=(self.context_window-self.max_tokens-25),
          system_message=system_message)
    else:
      messages = self.compress_messages(messages)

    if self.env["debug"] == "true":
      print(messages)

    # Code-Llama
    # Convert messages to prompt
    # (This only works if the first message is the only system message)
    prompt = messages_to_prompt(self, messages)
    # builtins.print(prompt)

    if self.model.startswith("openai:"):
      # [
      #  {"role": "system", "content": "You are a poetic assistant, be creative."},
      #  {"role": "user", "content": "Compose a poem that explains the concept of recursion in programming."}
      # ]
      openai_model = self.model[7:]
      if have_openai:
        # https://platform.openai.com/docs/assistants/overview
        if self.openai_client is None:
          self.openai_client = OpenAI()
        query = []
        if self.system_message != "":
          query.append({"role": "system", "content": self.system_message})
        query.extend(self.messages)

        completion = self.openai_client.chat.completions.create(
          # TODO: instructions=self.system_message # instead of passing it in the query
          model=openai_model,
          max_tokens=self.max_tokens, # 150 :?
          temperature=self.temperature,
          messages=query
        )
        response = completion.choices[0].message.content
        if "content" in self.messages[-1]:
          last_message = self.messages[-1]["content"]
        if self.env["chat.reply"] == "true":
          self.messages.append({"role": "assistant", "content": response})
        print(response)
        return
      else:
        print("pip install -U openai")
        print("export OPENAI_API_KEY=...")
        return
    else:
      # non-openai aka local-llama model
      if self.llama_instance == None:
        print("Cannot find the model")
        return
      try:
        response = self.llama_instance(
          prompt,
          stream=True,
          temperature=self.temperature,
          stop=[self.terminator],
          max_tokens=1750 # context window is set to 1800, messages are trimmed to 1000... 700 seems nice
        )
      except:
        if Ginterrupted:
          Ginterrupted = False
          return

    # Initialize message, function call trackers, and active block
    self.messages.append({})
    in_function_call = False
    self.active_block = None

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

      # Check if we're in a function call
      # Since Code-Llama can't call functions, we just check if we're in a code block.
      # This simply returns true if the number of "```" in the message is odd.
      if "content" in self.messages[-1]:
        condition = self.messages[-1]["content"].count("```") % 2 == 1
      else:
        # If it hasn't made "content" yet, we're certainly not in a function call.
        condition = False

      if condition:
        # We are in a function call.

        # Check if we just entered a function call
        if in_function_call == False:

          # If so, end the last block,
          self.end_active_block()

          # Print newline if it was just a code block or user message
          # (this just looks nice)
          self.messages[-2]["role"]

          # then create a new code block
          self.active_block = CodeBlock()

        # Remember we're in a function_call
        in_function_call = True

        # Now let's parse the function's arguments:

        # Code-Llama
        # Parse current code block and save to parsed_arguments, under function_call
        if "content" in self.messages[-1]:

          content = self.messages[-1]["content"]

          if "```" in content:
            # Split by "```" to get the last open code block
            blocks = content.split("```")
            current_code_block = blocks[-1]
            lines = current_code_block.split("\n")
            if content.strip() == "```": # Hasn't outputted a language yet
              language = None
            else:
              if lines[0] != "":
                language = lines[0].strip()
              else:
                language = "python"
                # In anticipation of its dumbassery let's check if "pip" is in there
                if len(lines) > 1:
                  if lines[1].startswith("pip"):
                    language = "shell"

            # Join all lines except for the language line
            code = '\n'.join(lines[1:]).strip("` \n")

            arguments = {"code": code}
            if language: # We only add this if we have it-- the second we have it, an interpreter gets fired up (I think? maybe I'm wrong)
              if language == "bash":
                language = "shell"
              arguments["language"] = language

          # Code-Llama won't make a "function_call" property for us to store this under, so:
          if "function_call" not in self.messages[-1]:
            self.messages[-1]["function_call"] = {}
          self.messages[-1]["function_call"]["parsed_arguments"] = arguments
      else:
        # We are not in a function call.
        # Check if we just left a function call
        if in_function_call == True:
          pass
        # Remember we're not in a function_call
        in_function_call = False
        # If there's no active block,
        if self.active_block == None:
          # Create a message block
          self.active_block = MessageBlock()
      if self.env["chat.live"] == "true":
        self.active_block.update_from_message(self.messages[-1])
      continue # end of for loop

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
        print(str(self.messages))
