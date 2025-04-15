import re
import argparse
import subprocess
# requires clang-format

parser = argparse.ArgumentParser(description="Format a C file using clang-format.")
parser.add_argument("filename", help="C source file to format")
args = parser.parse_args()

# Step 1: Format the file in-place using clang-format
try:
    subprocess.run(["clang-format", "-style={Language: C}", "-i", args.filename], check=True)
except (subprocess.CalledProcessError, FileNotFoundError):
    print("Error: clang-format is not installed or failed to run.")
    exit(1)

def is_function(s):
    return s and not s[0].isspace()

def is_control_structure(s):
    return s in {"if", "for", "while", "switch", "catch", "return"}

def fix_line(line):
    # Skip lines that are empty or only whitespace
    if not line.strip():
        return line

    # Match function calls like: foo(bar) => foo (bar)
    # Avoid if/for/while/catch/return and function *definitions*
    pattern = r'\b([a-zA-Z_]\w*)\('

    def replacer(match):
        name = match.group(1)
        if is_control_structure(name) or is_function(line):
            return match.group(0)  # No change
        return f'{name} ('

    return re.sub(pattern, replacer, line)

# Step 2: Read the file, transform it, and write it back
with open(arg, "r", encoding="utf-8") as f:
    lines = f.readlines()

with open(arg, "w", encoding="utf-8") as f:
    for line in lines:
        f.write(fix_line(line))
