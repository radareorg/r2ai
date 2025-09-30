# r2ai-server

Start ollama, llamacpp, llamafile, r2ai, kobaldcpp and other language model webservers using a the same syntax for all of them to simplify its launching and setup.

* Use -l to list the implementations available

You can install more via r2pm

* Use -m to list or select the model. Those models can be absolute paths or model names when downloaded via r2ai, which uses the hugging face api

## Running r2ai-server

- Get usage: `r2pm -r r2ai-server`
- List available servers: `r2pm -r r2ai-server -l`
- List available models: `r2pm -r r2ai-server -m`

On Linux, models are stored in `~/.r2ai.models/`. File `~/.r2ai.model` lists the default model and other models.

**Example launching a local Mistral AI server:**

```
$ r2pm -r r2ai-server -l r2ai -m mistral-7b-instruct-v0.2.Q2_K
[12/13/24 10:35:22] INFO     r2ai.server - INFO - [R2AI] Serving at port 8080                               web.py:336
```

