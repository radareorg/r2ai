import builtins
import re
import os
import sys
import traceback
import json
import platform
have_local = True
import getpass

try:
    import tokentrim
except Exception:
    have_local = False

from rich.rule import Rule
from signal import signal, SIGINT

from .env import R2AiEnv
from .large import Large
from .utils import merge_deltas
from .message_block import MessageBlock
from .code_block import CodeBlock
from .backend import kobaldcpp

from .models import get_hf_llm, new_get_hf_llm, get_default_model
from .voice import tts
from .const import R2AI_HOMEDIR
from . import LOGGER, logging
from .web import stop_http_server, server_running
from .progress import progress_bar

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

def is_litellm_model(model):
    import litellm
    litellm.drop_params = True
    provider = None
    model_name = None
    if model.startswith ("/"):
        return False
    if ":" in model:
        provider, model_name = model.split(":")
        if provider in [member.value for member in litellm.LlmProviders]:
            return True
    elif "/" in model:
        provider, model_name = model.split("/")
        if provider in litellm.models_by_provider and (model_name in litellm.models_by_provider[provider] or model in litellm.models_by_provider[provider]):
            return True
    return False

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
        self.env = R2AiEnv()
        self.system_message = ""
        self.env["llm.model"] = self.model ## TODO: dup. must get rid of self.model
        self.env["llm.gpu"] = "true"
        self.env["llm.layers"] = "-1"
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
        self.env["http.port"] = "8080"
        self.env["http.tabby"] = "false"
        self.env["http.path"] = ""
        self.env["http.verbose"] = "true" # not used yet
        self.env["http.chatctx"] = "false"
        self.env["debug_level"] = os.getenv("R2AI_LOG", "2")
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
        self.env["chat.rawdog"] = "false"
        
        self.env.add_callback("debug_level", lambda val: LOGGER.setLevel(int(val) * 10))

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
        mm = new_get_hf_llm(self, mmname, ctxwindow)
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

    @progress_bar("Thinking", color="yellow") 
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
        # Local model -- TODO: assume local models don't have : in the name?
        if (
            not self.model.startswith("openai:") and
            not self.model.startswith("openapi:") and
            not self.model.startswith("google:") and
            not self.model.startswith("kobaldcpp") and
            not self.model.startswith("bedrock:") and
            not is_litellm_model(self.model)
        ):
            self.logger = LOGGER.getChild(f"local:{self.model}")
            # Find or install Code-Llama
            try:
                ctxwindow = int(self.env["llm.window"])
                self.llama_instance = new_get_hf_llm(self, self.model, ctxwindow)
                if self.llama_instance is None:
                    self.logger.error("Cannot find model " + self.model)
                    return
            except Exception:
                traceback.print_exc()

        # If it was, we respond non-interactively
        self.messages.append({"role": "user", "content": message})
        response = None
        try:
            response = self.respond()
            self.clear_hints()
        except Exception:
            if Ginterrupted:
                Ginterrupted = False
            else:
                traceback.print_exc()
        self.end_active_block()
        return response
    
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
            from . import auto
            if(is_litellm_model(self.model)):
                response = auto.chat(self)
            else:
                self.llama_instance = new_get_hf_llm(self, self.model, int(self.env["llm.window"]))
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

        elif is_litellm_model(self.model):
            # [
            #  {"role": "system", "content": "You are a poetic assistant, be creative."},
            #  {"role": "user", "content": "Compose a poem that explains the concept of recursion in programming."}
            # ]
            from litellm import completion as litellm_completion
            completion = litellm_completion(
                model=self.model.replace(":", "/"),
                messages=self.messages,
                max_completion_tokens=maxtokens,
                temperature=float(self.env["llm.temperature"]),
                top_p=float(self.env["llm.top_p"]),
            )

            response = completion.choices[0].message.content
            if "content" in self.messages[-1]:
                last_message = self.messages[-1]["content"]
                if self.env["chat.reply"] == "true":
                    self.messages.append({"role": "assistant", "content": response})
                print(response)
                return response

        else:
            # non-openai aka local-llama model
            if self.llama_instance == None:
                self.logger.critical("Llama is not instantiated")
                return
            try:
                if type(self.terminator).__name__ == "list":
                    terminator = self.terminator
                else:
                    terminator = [self.terminator]
                chat_args = {
                    "stream": True,
                    "temperature": float(self.env["llm.temperature"]),
                    "repeat_penalty": float(self.env["llm.repeat_penalty"]),
                    "top_p": float(self.env["llm.top_p"]),
                    "top_k": int(self.env["llm.top_k"]),
                    "stop": terminator,
                    "max_tokens": maxtokens
                }
                if self.env["chat.rawdog"] == "true":
                    from .completion import messages_to_prompt
                    prompt = messages_to_prompt(self, messages)
                    response = self.llama_instance(prompt, **chat_args)
                else:
                    all_messages = messages.copy()
                    all_messages.insert(0, {"role": "system", "content": self.system_message})
                    response = self.llama_instance.create_chat_completion(all_messages, **chat_args)
            except Exception as err:
                traceback.print_exc()
                print(Exception, err)
                if Ginterrupted:
                    Ginterrupted = False
                    return

        if response is None:
            print("No response")
            ctxwindow = int(self.env["llm.window"])
            self.llama_instance = new_get_hf_llm(self, self.model, ctxwindow)
            return
        # Initialize message, function call trackers, and active block
        self.messages.append({})
        in_function_call = False
        self.active_block = MessageBlock()
        for chunk in response:
            if Ginterrupted:
                Ginterrupted = False
                break
            text = ''
            delta = None
            if self.env["chat.rawdog"] == "true":
                if "content" not in messages[-1]:
                    text = chunk["choices"][0]['text'].capitalize()
                    messages[-1] = { "content": '', "role": "assistant" }
                else:
                    text = chunk["choices"][0]['text']
                messages[-1] = merge_deltas(messages[-1], {"content": text})
            else:
                if "content" not in messages[-1]:
                    if "text" in chunk["choices"][0]['delta']:
                        text = chunk["choices"][0]['delta']["content"]
                    messages[-1] = { "content": text, "role": "assistant" }
                    delta = {"content": text}
                elif "content" in chunk['choices'][0]['delta']:
                    delta = {"content": chunk['choices'][0]['delta']['content']}
                # Accumulate deltas into the last message in messages
                if delta:
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
