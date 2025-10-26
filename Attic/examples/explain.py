#!/usr/bin/env r2pm -r r2ai
import sys

input_str = sys.stdin.read()

runline("-m TheBloke/Mistral-7B-Instruct-v0.1-GGUF")
print("/*")
runline("Explain this function in one sentence:\n```\n" + input_str.replace("\n", "\\n") + "\n```\n")
print("")
print("*/")
print(input_str)
