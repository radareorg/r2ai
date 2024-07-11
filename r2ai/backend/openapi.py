"""Implementation for kobaldcpp http api call using openai endpoint."""
import json
import requests

# MODEL="~/.r2ai.models/Lexi-Llama-3-8B-Uncensored_Q4_K_M.gguf"
# ./llama-server --in-prefix '### User: ' --prompt 5001 \
#	--in-suffix "### Assistant: " -m $MODEL

def chat(messages, uri='http://localhost:5001'):
    """Send a message to a kobaldcpp server and return the autocompletion response
    """
    if uri.endswith("/"):
        uri = uri[0:len(uri)-1]
#    url = f'{uri}/v1/completions'
    url = f'{uri}/v1/chat/completions'
    data = {
      "model": "gpt-3.5-turbo",
      "messages": messages
    }
    r = requests.post(url=url, data=json.dumps(data), timeout=600)
# print(r.text)
    j = json.loads(r.text)
    if "choices" in j:
        choice = j["choices"][0]
        if "text" in choice:
            return j["choices"][0]["text"]
        return choice["message"]["content"]
    return "No response"
