---
description: 'Suggest an improved function signature'
version: 0.1
author: pancake
command: ?e variables;afv;?e function name:;afd;?e current signature:?e afs
if-empty: exit
---
Analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the resturn. Do NOT print the function body. Output must be *ONLY* the function signature prefixed with the `'afs ` text