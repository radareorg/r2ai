from r2ai.pipe import get_r2_inst
import json
import builtins
import base64
from .pipe import get_filename
from . import LOGGER
import time
import sys
from io import StringIO
import subprocess
import os
is_plugin = False
try:
    import r2lang
    is_plugin = True
except Exception:
    is_plugin = False
    pass

def r2cmd(command: str):
    """
    Run a r2 command and return the output

    Parameters
    ----------
    command: str
        The r2 command to run

    Returns
    -------
    dict
        The output of the r2 command
    """
    r2 = get_r2_inst()
    r2.cmd('e scr.color=3')
    if command.startswith('r2 '):
        return "You are already in r2!"
    cmd = '{"cmd":' + json.dumps(command) + '}'
    res = r2.cmd(cmd)

    try:
        res = json.loads(res)
        if 'error' in res and res['error'] is True:
            error_message = res['error']
            log_messages = '\n'.join(log['message'] for log in res.get('logs', []))
            # return { 'type': 'error', 'output': log_messages }
            return log_messages
        
        return res['res']
    except json.JSONDecodeError:
        if type(res) == str:
            spl = res.strip().split('\n')
            if spl[-1].startswith('{"res":""'):
                res = '\n'.join(spl[:-1])
        return res
    except Exception as e:
        # return { 'type': 'error', 'output': f"Error running r2cmd: {e}\nCommand: {command}\nResponse: {res}" }
        return f"Error running r2cmd: {e}\nCommand: {command}\nResponse: {res}"
    
def run_python(command: str):
    """
    Run a python script and return the output

    Parameters
    ----------
    command: str
        The python script to run

    Returns
    -------
    str
        The output of the python script
    """
    r2 = get_r2_inst()
    res = ""
    is_plugin = False
    python_path = sys.executable
    try:
        proc = subprocess.run([python_path, '-c', command], 
                            capture_output=True,
                            text=True)
        res = proc.stdout
        if proc.stderr:
            res += proc.stderr
    except Exception as e:
        res = str(e)
    
    # if is_plugin:
    #     base64cmd = base64.b64encode(command.encode('utf-8')).decode('utf-8')
    #     res += r2cmd(f'#!python -e base64:{base64cmd} > .r2ai_tmp.log')
    #     res += r2cmd('cat .r2ai_tmp.log')
    #     r2cmd('rm .r2ai_tmp.log')
    # else:
    #     with open('r2ai_tmp.py', 'w') as f:
    #         f.write(command)
    #     r2 = get_r2_inst()
    #     res += r2cmd('#!python r2ai_tmp.py > .r2ai_tmp.log')
    #     time.sleep(0.1)
    #     res += r2cmd('!cat .r2ai_tmp.log')
    #     LOGGER.debug(f'run_python: {res}')
    #     # r2cmd('rm r2ai_tmp.py')
    #     # r2cmd('rm .r2ai_tmp.log')
    return res        
    

schemas = {
    "execute_binary": {
        "name": "execute_binary",
        "description": "Execute a binary with the given arguments and stdin",
        "parameters": {
        "type": "object",
        "properties": {
            "args": {
                "description": "The arguments to pass to the binary. Do not include the file name.",
                "type": "array",
                "items": {
                    "type": "string"
                }
            },
            "stdin": {
                "type": "string"
            }
            }
        }
    }
}

def execute_binary(args: list[str] = [], stdin: str = ""):
    filename = get_filename()
    if filename:
        if os.path.isabs(filename):
            abs_path = os.path.abspath(filename)
            if os.path.exists(abs_path):
                filename = abs_path
        else:
            cwd_path = os.path.join(os.getcwd(), filename) 
            if os.path.exists(cwd_path):
                filename = cwd_path
        try:
            cmd = [filename] + args
            proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
            res = proc.stdout
            if proc.stderr:
                res += proc.stderr
            return res
        except Exception as e:
            return str(e)
    return ""
    # r2 = get_r2_inst()
    # if stdin:
    #     r2.cmd(f'dor stdin={json.dumps(stdin)}')
    # if len(args) > 0:
    #     r2.cmd(f"ood {' '.join(args)}")
    # else:
    #     r2.cmd("ood")
    # res = r2cmd("dc")
    # return res



def print_tool_call(msg):
    if msg['function']['name'] == 'r2cmd':
        builtins.print('\x1b[1;32m> \x1b[4m' + msg['function']['arguments']['command'] + '\x1b[0m')
    elif msg['function']['name'] == 'run_python':
        builtins.print('\x1b[1;32m> \x1b[4m' + "#!python" + '\x1b[0m')
        builtins.print(msg['function']['arguments']['command'])
    elif msg['function']['name'] == 'execute_binary':
        filename = get_filename() or 'bin'
        stdin = msg['function']['arguments']['stdin'] if 'stdin' in msg['function']['arguments'] else None
        args = msg['function']['arguments']['args'] if 'args' in msg['function']['arguments'] else []
        cmd = filename
        if args and len(args) > 0:
            cmd += ' ' + ' '.join(args)
        if stdin and len(stdin) > 0:
            cmd += f' stdin={stdin}'
        builtins.print('\x1b[1;32m> \x1b[4m' + cmd + '\x1b[0m')
