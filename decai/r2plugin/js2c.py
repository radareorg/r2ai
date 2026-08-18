#!/usr/bin/env python3
"""Convert a script file into a C buffer named decai_qjs (same output as `rax2 -C` + sed)."""

import sys

data = open(sys.argv[1], "rb").read()
with open(sys.argv[2], "w") as f:
    f.write("const unsigned char decai_qjs[] = {\n")
    for i in range(0, len(data), 16):
        f.write("  %s,\n" % ", ".join("0x%02x" % b for b in data[i:i + 16]))
    f.write("};\nconst unsigned int decai_qjs_len = %d;\n" % len(data))
