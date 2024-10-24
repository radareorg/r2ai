import os
import sys
from .const import R2AI_HISTFILE, R2AI_HOMEDIR, R2AI_RCFILE, R2AI_USERDIR
from .models import models

mmm = []
for m in sorted(models().split("\n")):
    if m.startswith("-m "):
        mmm.append(m[3:])
eee = []
hhh = [
        "R2AI_USERDIR",
        "R2AI_PLUGDIR",
        "R2AI_HOMEDIR",
        "R2AI_RCFILE",
        "R2AI_HISTFILE",
    ]

def autocomplete_files(flag, second_word):
    cwd = second_word[:second_word.rfind('/') + 1]
    if cwd == "": cwd = "./"
    files = [cwd + c + "/" for c in os.listdir(cwd)]
    return [flag + " " + s for s in files if s and s.startswith(second_word)]

class MyCompleter(object):  # Custom completer
    def __init__(self, options):
        self.options = sorted(options)

    def complete(self, text, state):
        line = readline.get_line_buffer()
        splits = line.split()
        first_word = splits[0].strip() if len(line) > 0 else ""
        second_word = splits[1].strip() if len(splits) > 1 else ""
        if state == 0:
            if not text:
                self.matches = self.options[:]
            elif first_word == ".":
                self.matches = autocomplete_files(".", second_word)
            elif first_word == "-e":
                if second_word == "":
                    self.matches = ["-e " + c + ' ' for c in eee]
                else:
                    self.matches = ["-e " + s for s in eee if s and s.startswith(second_word)]
            elif first_word == "-rf":
                self.matches = autocomplete_files("-rf", second_word)
            elif first_word == "-i":
                self.matches = autocomplete_files("-i", second_word)
            elif first_word == "-f":
                self.matches = autocomplete_files("-f", second_word)
            elif first_word == "-H":
                if second_word == "":
                    self.matches = ["-H " + c + ' ' for c in hhh]
                else:
                    self.matches = ["-H " + s for s in hhh if s and s.startswith(second_word)]
            elif first_word == "-m":
                if second_word.startswith("/") or second_word.startswith("."):
                    self.matches = autocomplete_files("-m", second_word)
                elif second_word == "":
                    self.matches = ["-m " + c + ' ' for c in mmm]
                else:
                    self.matches = ["-m " + s for s in mmm if s and s.startswith(second_word)]
            else:
                self.matches = [s for s in self.options if s and s.startswith(text)]
        try:
            return self.matches[state]
        except IndexError:
            return None

    def display_matches(self, substitution, matches, longest_match_length):
        line_buffer = readline.get_line_buffer()
        columns = os.environ.get("COLUMNS", 80)
        print()
        tpl = "{:<" + str(int(max(map(len, matches)) * 1.2)) + "}"
        buffer = ""
        for match in matches:
            match = tpl.format(match[len(substitution):])
            if len(buffer + match) > columns:
                print(buffer)
                buffer = ""
            buffer += match
        if buffer:
            print(buffer)
        print("> ", end="")
        print(line_buffer, end="")
        sys.stdout.flush()

commands = []
commands.extend(sorted([
    "?", ".", "..", ":", "' ", "!",
    "-a", "-A", "-k", "-c", "-e", "-f", "-h", "-H",
    "-i", "-m", "-M", "-MM", "-n", "-q", "-L",
    "-r", "-r2", "-rf", "-repl",
    "-R", "-t", "-v", "-w", "q"
]))

commands = [x.split(' ')[0] for x in commands]

have_readline = False
try:
    import readline
    import rlcompleter
    have_readline = True
except Exception:
    have_readline = True
    pass # readline not available

def tab_hist():
    if not have_readline:
        print("Cannot find readline", file=sys.stderr)
        return False

def tab_evals(x):
    global eee
    eee = sorted(x)

def tab_write():
    if not have_readline:
        print("Cannot find readline", file=sys.stderr)
        return False
    readline.write_history_file(R2AI_HISTFILE)

def tab_list():
    global readline
    if not have_readline:
        return []
    amount = readline.get_current_history_length()
    res = []
    for i in range(1, amount):
        item = readline.get_history_item(i)
        res.append(f"{i}  {item}")
    return res

def tab_init():
    if not have_readline:
        print("Cannot find readline", file=sys.stderr)
        return False
    completer = MyCompleter(list(set(commands)))
    try:
        readline.read_history_file(R2AI_HISTFILE)
    except FileNotFoundError:
        pass
    except Exception:
        pass
    readline.set_completer(completer.complete)
    readline.set_completer_delims('\t\n;')
    readline.set_completion_display_matches_hook(completer.display_matches)
    if readline.__doc__.find("GNU") != -1:
        readline.parse_and_bind('tab: complete')
    else:
        readline.parse_and_bind("bind ^I rl_complete")
