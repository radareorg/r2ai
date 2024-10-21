from r2ai.pipe import get_r2_inst
import json
import builtins

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
    with open('r2ai_tmp.py', 'w') as f:
        f.write(command)
    r2 = get_r2_inst()
    res = r2.cmd('#!python r2ai_tmp.py')
    r2.cmd('rm r2ai_tmp.py')
    return res
