import os
import traceback
import r2pipe

have_rlang = False
r2lang = None

r2 = None

class FakeLang:
    def __init__(self, r2 = None):
        self.r2 = r2

    def ai(self, x):
        try:
            from r2ai.repl import r2ai_singleton, runline2
            ai = r2ai_singleton()
            if ai is None:
                print("No global r2ai instance found")
                return ""
            return runline2(ai, x)
        except Exception:
            traceback.print_exc()
            return None

    def cmd(self, x):
        if self.r2 is None:
            return ""
        if hasattr(self.r2, "_cmd"):
            return self.r2.cmd(x)
        return ""

try:
    import r2lang
    have_rlang = True
except Exception:
    import r2pipe
    try:
        if r2pipe.in_r2():
            r2lang = FakeLang(r2pipe.open())
            r2lang.cmd("?V") # r2pipe throws only here
        else:
            raise Error("must spawn")
    except Exception:
        try:
            have_rlang = False
            if os.environ.get('R2AI') is None:
                ppid = os.getppid()
                os.environ["R2AI"] = "1"
                r2lang = FakeLang(r2pipe.open("/bin/ls"))
            else:
                r2lang = FakeLang(None)
        except Exception:
            print("Cannot instantiate this FakeLang class with r2pipe")
            r2lang = FakeLang(None)

def r2singleton():
    global r2lang
    return r2lang

def get_r2_inst():
    global r2
    return r2

def open_r2(file, flags=[]):
    global r2
    r2 = r2pipe.open(file, flags=flags)
