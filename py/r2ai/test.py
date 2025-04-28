import builtins
from .tools import run_python, execute_binary, r2cmd
import subprocess
from .pipe import get_filename
import time
py_code = """
print('hello test')
"""

def run_test(args):
    if not args or len(args) == 0:
        res = run_python(py_code).strip()
        print(f"run_python: {res}", len(res))
        assert res == "hello test"
        print("run_python: test passed")
        r2cmd("o--;o /bin/ls")
        res = execute_binary(args=["-d", "/etc"]).strip()
        subp = subprocess.run(["/bin/ls", "-d", "/etc"], capture_output=True, text=True)
        print("exec result", res)
        print("subp result", subp.stdout)
        assert ''.join(res).strip() == subp.stdout.strip()
        print("execute_binary with args: test passed")
    else:
        cmd, *args = args.split(" ", 1)
        if cmd == "get_filename":
            builtins.print(get_filename())
        elif cmd == "run_python":
            builtins.print(f"--- args ---")
            builtins.print(args)
            builtins.print(f"--- end args ---")
            builtins.print(f"--- result ---")
            builtins.print(run_python(args[0]))
            builtins.print(f"--- end result ---")
        elif cmd == "r2cmd":
            builtins.print(f"--- {args} ---")
            builtins.print(r2cmd(args))
            builtins.print("--- end ---")
