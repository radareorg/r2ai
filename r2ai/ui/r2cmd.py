from r2ai.pipe import get_r2_inst
import json
import builtins

def r2cmd(command: str):
    r2 = get_r2_inst()
    cmd = '{"cmd":"' + command + '"}'
    res = r2.cmd(cmd)
    try:
        res = json.loads(res)
        if 'error' in res and res['error'] is True:
            error_message = res['error']
            log_messages = '\n'.join(log['message'] for log in res.get('logs', []))
            return { 'type': 'error', 'output': log_messages }
        
        return { 'type': 'success', 'output': res['res'] }
    except Exception as e:
        raise Exception(f"Error running r2cmd: {e}\nCommand: {command}\nResponse: {res}") 
