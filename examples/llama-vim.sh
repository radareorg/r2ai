#!/bin/sh
r2pm -r llama-server  \
    --port 8012 -ngl 99 -fa -ub 1024 -b 1024 -dt 0.1 \
    --ctx-size 0 --cache-reuse 256 -m ~/.r2ai.models/qwen2.5-coder-7b-instruct-q3_k_m.gguf
