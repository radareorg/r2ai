have_rlang = False
r2lang = None

class FakeLang:
    def __init__(self, r2):
        self.r2 = r2
    def cmd(self, x):
        r = self.r2.cmd(x)
        return r

try:
    import r2lang
    have_rlang = True
except:
    import r2pipe
    try:
        r2lang = FakeLang(r2pipe.open())
        r2lang.cmd("?V") # r2pipe throws only here
    except:
        try:
            r2lang = FakeLang(r2pipe.open("/bin/ls"))
        except:
            print("Cannot instantiate this FakeLang class with r2pipe")
            pass

def r2singleton():
    return r2lang
