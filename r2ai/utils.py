import json
import subprocess

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
