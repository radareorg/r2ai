import builtins
from .utils import merge_deltas
from .message_block import MessageBlock
from .code_block import CodeBlock
from .index import main_indexer
from .models import get_hf_llm, new_get_hf_llm, get_default_model

import os
import traceback
import json
import platform

have_rlang = False
try:
	import r2lang
	have_rlang = True
except:
	pass

import getpass
import tokentrim as tt
# from rich import print
# from rich.markdown import Markdown
from rich.rule import Rule

import signal
import sys
try:
	import r2lang
	have_rlang = True
	print = r2lang.print
except:
	pass

Ginterrupted = False
def signal_handler(sig, frame):
	global Ginterrupted
	Ginterrupted = True
	print("^C")
	sys.exit(0) # throws exception

signal.signal(signal.SIGINT, signal_handler)
# print('Press Ctrl+C')
# signal.pause()

def Markdown(x):
	return x

# Function schema for gpt-4
function_schema = {
  "name": "run_code",
  "description":
  "Executes code on the user's machine and returns the output",
  "parameters": {
    "type": "object",
    "properties": {
      "language": {
        "type": "string",
        "description":
        "The programming language",
        "enum": ["python", "shell", "javascript", "html"]
      },
      "code": {
        "type": "string",
        "description": "The code to execute"
      }
    },
    "required": ["language", "code"]
  },
}

def messages_to_prompt(self,messages):
  for message in messages:
    # Happens if it immediatly writes code
    if "role" not in message:
      message["role"] = "assistant"

  if "q4_0" in self.model.lower():
    formatted_messages = template_q4im(self, messages)
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
    formatted_messages = template_uncensored(self, messages)
  elif "python" in self.model.lower():
    print("codellama-python model is not working well yet")
    formatted_messages = template_llamapython(self, messages)
  elif "tinyllama" in self.model.lower():
    formatted_messages = template_tinyllama(self, messages)
  elif "TinyLlama" in self.model.lower():
    formatted_messages = template_tinyllama(self, messages)
  else:
    formatted_messages = template_llama(self, messages)

  if "DEBUG" in self.env:
    builtins.print(formatted_messages)
  return formatted_messages


def template_q4im(self,messages):
  self.terminator = "<|im_end|>"
  formatted_messages = ""
  try:
    system_prompt = messages[0]['content'].strip()
    if system_prompt != "":
      formatted_messages += "\{\"text\":\"{"+system_prompt+"}\"\}"
      # formatted_messages = f"[STDIN] {system_prompt} [/STDIN]\n"
      # formatted_messages = f"/imagine prompt: {system_prompt}\n"
    for index, item in enumerate(messages[1:]):
        item['role']
        content = item['content'].strip()
        formatted_messages += f"<|im_start|>{content}<|im_end|>"
        formatted_messages += "\{\"text\":\"{"+content+"}\"\}"
    formatted_messages += f"<|im_start|>\n"
    print("```" + formatted_messages + "```")
  except:
    traceback.print_exc()
  return formatted_messages

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
      elif role == "assistant":
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
      elif role == 'function':
          formatted_messages += f"user {content} "
      elif role == 'assistant':
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
  formatted_messages += "\n[INST]Answer: "
  return formatted_messages

def template_alpaca(self,messages):
  self.terminator = "###"
  system_prompt = messages[0]['content'].strip()
  if system_prompt != "":
      formatted_messages = f"### Instruction:\n{system_prompt}\n"
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
          formatted_messages += f"### Instruction:\n{content}\n"
      else:
          formatted_messages += f"### Response:\n{content}\n"
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
      else:
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
      role = item['role']
      content = item['content']
      if role == 'user':
          formatted_messages += f"{content}[/INST] "
      elif role == 'function':
          formatted_messages += f"Output: {content}[/INST] "
      elif role == 'assistant':
          formatted_messages += f"{content}</s><s>[INST]"
  # Remove the trailing '<s>[INST] ' from the final output
  if formatted_messages.endswith("<s>[INST]"):
      formatted_messages = formatted_messages[:-9]
  return formatted_messages

class Interpreter:

  def __init__(self):
    self.messages = []
    self.use_indexer = True
    self.temperature = 0.002
    self.terminator = "</s>"
    self.api_key = None
    self.auto_run = False
    self.model = get_default_model()
    self.last_model = ""
    self.live_mode = not have_rlang
    self.env = {}
    self.api_base = None # Will set it to whatever OpenAI wants
# self.context_window = 16096 # For local models only BURNS!
    self.context_window = 4096 # For local models only // input max length - TODO. make it configurable
    # self.max_tokens = 750 # For local models only
    self.max_tokens = 1750 # For local models only // make it configurable

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
        print(Markdown(f"**Removed message:** `\"{message['content'][:30]}...\"`"))
      elif 'function_call' in message:
        print(Markdown(f"**Removed codeblock**")) # TODO: Could add preview of code removed here.

  def chat(self, message=None, return_messages=False):
    global Ginterrupted
    if self.last_model != self.model:
      self.llama_instance = None
      self.last_model = self.model
    if not message:
      self.end_active_block()
      print("Missing message")
      return
    if self.use_indexer:
      matches = main_indexer(message)
      if len(matches) > 0:
        newmsg = "<<SYS>>"
        for m in matches:
          newmsg += f"{m}.\n"
        message = newmsg + "<</SYS>>\n" + message
    if "DEBUG" in self.env:
      print(message)
#    print(message)
    # Code-Llama
    if self.llama_instance == None:
      # Find or install Code-Llama
      try:
        debug_mode = "DEBUG" in self.env
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
    except:
        if Ginterrupted:
            Ginterrupted = False
        else:
            traceback.print_exc()
    self.end_active_block()
    if return_messages:
        return self.messages

  def end_active_block(self):
    if self.active_block:
      self.active_block.end()
      self.active_block = None

  def environment(self):
    kvs = ""
    for k in self.env.keys():
        if k != "DEBUG":
            kvs += k + ": " + self.env[k] + "\n"
    if len(kvs) == 0:
        return ""
    # info += f"[User Info]\nName: {username}\nCWD: {current_working_directory}\nOS: {operating_system}"
    return "[User Info]\n" + kvs

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

    messages = tt.trim(self.messages,
        max_tokens=(self.context_window-self.max_tokens-25),
        system_message=system_message)

    # DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG
    if "DEBUG" in self.env:
      print(messages)

    # Make LLM call
    self.terminator = "</s>"
    # Code-Llama
    # Convert messages to prompt
    # (This only works if the first message is the only system message)
    prompt = messages_to_prompt(self,messages)

    if "DEBUG" in self.env:
      # we have to use builtins bizarrely! because rich.print interprets "[INST]" as something meaningful
      builtins.print("TEXT PROMPT SEND TO LLM:\n", prompt)

    if self.llama_instance == None:
      print("Cannot find the model")
      return
    # Run Code-Llama
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
      if not self.live_mode:
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
      if self.live_mode:
        self.active_block.update_from_message(self.messages[-1])
      continue # end of for loop

    if not self.live_mode:
      try:
        output_text = self.messages[-1]["content"].strip()
        r2lang.print(output_text)
      except:
        print(str(self.messages))
