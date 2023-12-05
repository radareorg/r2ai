import os
runline("-R")
runline("-r I am a radare2 developer writing patches in C")
runline("-m TheBloke/Mistral-7B-Instruct-v0.1-GGUF")
os.system("git diff @^ > .a.patch")
runline("-i .a.patch write a commit message starting with a capital letter for this diff. Commit messages cannot be longer than 60 characters.")
runline("-R")
runline("-i .a.patch write an explanation to be submmited in the pull request, explanation should be short and contain less than 3 items/highlights")
os.system("rm .a.patch")
