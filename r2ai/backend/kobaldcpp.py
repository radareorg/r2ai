"""Implementation for kobaldcpp http api call using openai endpoint."""
import json
import requests

PROMPT="""Your name is r2ai, an assistant for radare2.
User will ask about actions and you must respond with the radare2 command
associated or the answer to the question. Be precise and concise when answering
"""

def chat(message, uri='http://localhost:5001'):
    """Send a message to a kobaldcpp server and return the autocompletion response
    """
    url = f'{uri}/v1/completions'
    data = {
        "max_length": 1024,
        "prompt": message,
        "quiet": True,
        "n": 1,
        "echo": False,
        "stop": ["\nUser:"],
        "rep_pen": 1.1,
        "rep_pen_range": 256,
        "rep_pen_slope": 1,
        "temperature": 0.3,
        "tfs": 1,
        "top_a": 0,
        "top_k": 100,
        "top_p": 0.9,
        "typical": 1
    }
    r = requests.post(url=url, data=json.dumps(data), timeout=600)
    j = json.loads(r.text)
    i = j["choices"][0]["text"]
    return i

#m = slurp("/Users/pancake/prg/r2ai/doc/data/quotes.txt")
#AI="AI"
#US="User"
#CTX="Context"
#while True:
#    message = input()
#    qmsg = f"{CTX}:\n```{fullmsg}\n```\n{US}: {message}\n"
#    r = query_completions(qmsg)
#    r = r.replace(f"{AI}:", "").strip()
#    r = r.replace(f"{US}:", "").strip()
#    r = r.replace("```", "").strip()
#    print(r)
#    fullmsg = f"{fullmsg}\n{US}: {message}\n{AI}: {r}\n"
