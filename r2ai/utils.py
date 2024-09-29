import json
import subprocess

# TODO: move into utils
from datetime import datetime
def get_timez():
    return datetime.utcnow().isoformat(timespec='microseconds') + 'Z'

def merge_deltas(original, delta):
    """
    Pushes the delta into the original and returns that.

    Great for reconstructing OpenAI streaming responses -> complete message objects.
    """
    for key, value in delta.items():
        if isinstance(value, dict):
            if key not in original:
                original[key] = value
            else:
                merge_deltas(original[key], value)
        else:
            if key in original:
                original[key] += value
            else:
                original[key] = value
    return original

def slurp(f):
    fd = open(f, errors="ignore")
    data = fd.read()
    fd.close()
    return str(data)

def dump(f, x):
    fd = open(f, "w")
    fd.write(x)
    fd.close()

def syscmdstr(cmd):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    return output.decode().strip()


def filter_print(*args, **kwargs):
    _args = []
    filter = None
    if "filter" in kwargs:
        filter = kwargs["filter"]
        del kwargs["filter"]
    for a in args:
        new = ""
        lines = str(a).splitlines()
        if len(lines) > 1:
            for line in lines:
                if filter is not None:
                    if filter in line:
                        new += line + "\n"
                else:
                    new += line + "\n"
        else:
            if filter is not None:
                if filter in str(a):
                    new += str(a)
            else:
                new += str(a)
        _args.append(new)
    
    print(*_args, **kwargs)