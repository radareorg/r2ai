"""

This code is based on OpenInterpreter. I want to thanks all the contributors to this project as they made it possible to build r2ai taking their code as source for this.

Kudos to Killian and all the contributors. You may want to chat with them in Discord https://discord.gg/6p3fD6rBVm

--pancake

"""

import builtins
from .utils import merge_deltas, parse_partial_json
from .message_block import MessageBlock
from .code_block import CodeBlock
from .code_interpreter import CodeInterpreter
from .get_hf_llm import get_hf_llm, new_get_hf_llm

import os
import time
import traceback
import json
import platform
import openai
import litellm
import pkg_resources

have_rlang = False
try:
  import r2lang
  have_rlang = True
except:
  pass

import getpass
import requests
import readline
import tokentrim as tt
# from rich import print
# from rich.markdown import Markdown
from rich.rule import Rule

import signal
import sys

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)

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
        "enum": ["python", "R", "shell", "applescript", "javascript", "html"]
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
    formatted_messages = template_q4im(self,messages)
  elif "uncensor" in self.model.lower():
    formatted_messages = template_uncensored(self,messages)
  elif "falcon" in self.model.lower():
    formatted_messages = template_falcon(self,messages)
  else:
    formatted_messages = template_llama(self,messages)

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
        role = item['role']
        content = item['content'].strip()
        formatted_messages += f"<|im_start|>{content}<|im_end|>"
        formatted_messages += "\{\"text\":\"{"+content+"}\"\}"
    formatted_messages += f"<|im_start|>\n"
    print("```" + formatted_messages + "```")
  except:
    traceback.print_exc()
    pass
  return formatted_messages

def template_uncensored(self,messages):
#{'role': 'function', 'name': 'run_code', 'content': 'User decided not to run this code.'}
#{'role': 'user', 'content': 'tenis'}
#{'content': "\nI'm here to help you with any questions or tasks you have! What can I assist you with today?", 'role': 'assistant'}
#{'role': 'user', 'content': "thehre's no purpose on this"}
#{'role': 'assistant'}
#{'role': 'user', 'content': 'force a crash'}
  self.terminator = "###"
#self.terminator = "\n"
#  self.terminator = "</s>"
  formatted_messages = ""
  try:
    system_prompt = messages[0]['content'].strip()
    if system_prompt != "":
      formatted_messages = f"{system_prompt}\n"
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
          formatted_messages += f"### Assistant: {content}\n"
    formatted_messages += f"### Human:"
    # print("```" + formatted_messages + "```")
  except:
    traceback.print_exc()
    pass
  return formatted_messages

def template_falcon(self,messages):
  self.terminator = "}";
  formatted_messages = ""
  for message in messages:
    formatted_messages += f"{message['role'].capitalize()}: {message['content']}"
  return formatted_messages.strip()

def template_llama(self,messages):
  # Llama prompt template
  # Extracting the system prompt and initializing the formatted string with it.
  self.terminator = "</s>"
  system_prompt = messages[0]['content'].strip()
  if system_prompt != "":
      formatted_messages = f"<s>[INST]<<SYS>>\n{system_prompt}\n<</SYS>>"
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
          formatted_messages += f"{content} </s><s>[INST] "
  # Remove the trailing '<s>[INST] ' from the final output
  if formatted_messages.endswith("<s>[INST]"):
      formatted_messages = formatted_messages[:-10]
  return formatted_messages

class Interpreter:

  def __init__(self):
    self.messages = []
    self.temperature = 0.002
    self.terminator = "</s>"
    self.api_key = None
    self.auto_run = False
    self.local = True
    self.model = "TheBloke/CodeLlama-34B-Instruct-GGUF"
    self.live_mode = not have_rlang
    self.env = {}
    self.api_base = None # Will set it to whatever OpenAI wants
# self.context_window = 16096 # For local models only BURNS!
    self.context_window = 4096 # For local models only // input max length
    # self.max_tokens = 750 # For local models only
    self.max_tokens = 1750 # For local models only
    # Azure OpenAI
    self.use_azure = False
    self.azure_deployment_name = None

    # Get default system message
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, 'system_message.txt'), 'r') as f:
      self.system_message = f.read().strip()

    # Store Code Interpreter instances for each language
    self.code_interpreters = {}

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
    username = getpass.getuser()
    current_working_directory = os.getcwd()
    operating_system = platform.system()

#   info += f"[User Info]\nName: {username}\nCWD: {current_working_directory}\nOS: {operating_system}"

    if not self.local:

      # Open Procedures is an open-source database of tiny, structured coding tutorials.
      # We can query it semantically and append relevant tutorials/procedures to our system message:

      # Use the last two messages' content or function call to semantically search
      query = []
      for message in self.messages[-2:]:
        message_for_semantic_search = {"role": message["role"]}
        if "content" in message:
          message_for_semantic_search["content"] = message["content"]
        if "function_call" in message and "parsed_arguments" in message["function_call"]:
          message_for_semantic_search["function_call"] = message["function_call"]["parsed_arguments"]
        query.append(message_for_semantic_search)

      # Use them to query Open Procedures
      url = "https://open-procedures.replit.app/search/"

      try:
        relevant_procedures = requests.get(url, data=json.dumps(query)).json()["procedures"]
        info += "\n\n# Recommended Procedures\n" + "\n---\n".join(relevant_procedures) + "\nIn your plan, include steps and, if present, **EXACT CODE SNIPPETS** (especially for depracation notices, **WRITE THEM INTO YOUR PLAN -- underneath each numbered step** as they will VANISH once you execute your first line of code, so WRITE THEM DOWN NOW if you need them) from the above procedures if they are relevant to the task. Again, include **VERBATIM CODE SNIPPETS** from the procedures above if they are relevent to the task **directly in your plan.**"
      except:
        # For someone, this failed for a super secure SSL reason.
        # Since it's not stricly necessary, let's worry about that another day. Should probably log this somehow though.
        pass

    elif self.local:
      # Tell Code-Llama how to run code.
      info += "" # \n\nTo run code, write a fenced code block (i.e ```python, R or ```shell) in markdown. When you close it with ```, it will be run. You'll then be given its output."
      # We make references in system_message.txt to the "function" it can call, "run_code".

    return info

  def reset(self):
    """
    Resets the interpreter.
    """
    self.messages = []
    self.code_interpreters = {}

  def load(self, messages):
    self.messages = messages


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

  def handle_help(self, arguments):
    commands_description = {
      "%debug [true/false]": "Toggle debug mode. Without arguments or with 'true', it enters debug mode. With 'false', it exits debug mode.",
      "%reset": "Resets the current session.",
      "%undo": "Remove previous messages and its response from the message history.",
      "%save_message [path]": "Saves messages to a specified JSON path. If no path is provided, it defaults to 'messages.json'.",
      "%load_message [path]": "Loads messages from a specified JSON path. If no path is provided, it defaults to 'messages.json'.",
      "%help": "Show this help message.",
    }

    base_message = [
      "> **Available Commands:**\n\n"
    ]

    # Add each command and its description to the message
    for cmd, desc in commands_description.items():
      base_message.append(f"- `{cmd}`: {desc}\n")

    additional_info = [
      "\n\nFor further assistance, please join our community Discord or consider contributing to the project's development."
    ]

    # Combine the base message with the additional info
    full_message = base_message + additional_info

    print(Markdown("".join(full_message)))

  def handle_reset(self, arguments):
    self.reset()
    print(Markdown("> Reset Done"))

  def default_handle(self, arguments):
    print(Markdown("> Unknown command"))
    self.handle_help(arguments)

  def handle_save_message(self, json_path):
    if json_path == "":
      json_path = "messages.json"
    if not json_path.endswith(".json"):
      json_path += ".json"
    with open(json_path, 'w') as f:
      json.dump(self.messages, f, indent=2)

    print(Markdown(f"> messages json export to {os.path.abspath(json_path)}"))

  def handle_load_message(self, json_path):
    if json_path == "":
      json_path = "messages.json"
    if not json_path.endswith(".json"):
      json_path += ".json"
    with open(json_path, 'r') as f:
      self.load(json.load(f))

    print(Markdown(f"> messages json loaded from {os.path.abspath(json_path)}"))

  def handle_command(self, user_input):
    # split the command into the command and the arguments, by the first whitespace
    switch = {
      "help": self.handle_help,
      "reset": self.handle_reset,
      "save_message": self.handle_save_message,
      "load_message": self.handle_load_message,
      "undo": self.handle_undo,
    }

    user_input = user_input[1:].strip()  # Capture the part after the `%`
    command = user_input.split(" ")[0]
    arguments = user_input[len(command):].strip()
    action = switch.get(command, self.default_handle)  # Get the function from the dictionary, or default_handle if not found
    action(arguments)  # Execute the function

  def chat(self, message=None, return_messages=False):
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

    # Check if `message` was passed in by user
    if message:
      # If it was, we respond non-interactivley
      self.messages.append({"role": "user", "content": message})
      self.respond()

    else:
      # If it wasn't, we start an interactive chat
      while True:
        try:
          user_input = input("> ").strip()
        except EOFError:
          break
        except KeyboardInterrupt:
          break

        # Use `readline` to let users up-arrow to previous user messages,
        # which is a common behavior in terminals.
        readline.add_history(user_input)

        # If the user input starts with a `%` or `/`, it's a command
        if user_input.startswith("%") or user_input.startswith("/"):
          self.handle_command(user_input)
          continue

        # Add the user message to self.messages
        self.messages.append({"role": "user", "content": user_input})

        # Respond, but gracefully handle CTRL-C / KeyboardInterrupt
        try:
          self.respond()
        except KeyboardInterrupt:
          pass
        finally:
          # Always end the active block. Multiple Live displays = issues
          self.end_active_block()

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
    # Add relevant info to system_message
    # (e.g. current working directory, username, os, etc.)
    info = self.get_info_for_system_message()

    # This is hacky, as we should have a different (minified) prompt for CodeLLama,
    # but for now, to make the prompt shorter and remove "run_code" references, just get the first 2 lines:
    if self.local:
      self.system_message = "\n".join(self.system_message.split("\n")[:2])
      # self.system_message += "\nOnly do what the user asks you to do, then ask what they'd like to do next."

    system_message = self.system_message + "\n\n" + info
    system_message += self.environment()

    if self.local:
      messages = tt.trim(self.messages, max_tokens=(self.context_window-self.max_tokens-25), system_message=system_message)
    else:
      messages = tt.trim(self.messages, self.model, system_message=system_message)

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

    # Run Code-Llama
    response = self.llama_instance(
      prompt,
      stream=True,
      temperature=self.temperature,
      stop=[self.terminator],
      max_tokens=1750 # context window is set to 1800, messages are trimmed to 1000... 700 seems nice
    )

    # Initialize message, function call trackers, and active block
    self.messages.append({})
    in_function_call = False
    llama_function_call_finished = False
    self.active_block = None

    for chunk in response:
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
          last_role = self.messages[-2]["role"]

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
          llama_function_call_finished = True
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
