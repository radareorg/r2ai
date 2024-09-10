import platform
import json
import re
import time
from threading import Thread, Event
from .utils import get_timez
from . import LOGGER

ores = ""

kill_event = None
server = None
server_thread = None

# OpenAI API endpoint here
def handle_v1_completions_default(self, ai, obj, runline2, method):
    if "prompt" in obj:
        res = runline2(ai, obj["prompt"])
        resobj = {}
        resobj["choices"] = [{
            "text": res
        }]
        resjson = json.dumps(resobj)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(bytes(f'{resobj}', 'utf-8'))
    self.send_response(404)
    self.end_headers()
    return True

# {"messages": [ {"role": "user", "content": "Explain the following code:n'''ndata = {n    "messages": [n        {n            "role": "user",n            "content": "Explain code:n" + c_code,n            "stream": "true",n            "max_tokens": 7100,n            "temperature": 0.2n        }n    ],n}n'''"}],x0dx0a"model":"", "stream": "true", "max_tokens": 7100, "temperature": 0.2# }
def handle_v1_chat_completions(self, ai, obj, runline2, method):
    print("/v1/chat/completions")
    if obj == None:
        print("ObjNone")
        self.send_response(200)
        self.end_headers()
        return True
    if "messages" not in obj:
        return handle_v1_completions_default(self, ai, obj, runline2, method)
    user = []
    system = []
    for m in obj["messages"]:
        if m["role"] == "system":
            system.append(m["content"])
        else:
            user.append(m["content"])
    rolequery = "\n".join(system)
    codequery = "\n".join(user)
    WANTCTX = ai.env["http.chatctx"] == "true"
    if not WANTCTX:
        runline2(ai, "-R")
    runline2(ai, "-r " + rolequery)
    response = json.loads('''{
  "id": "r2ai",
  "object": "chat.completion.chunk",
  "created": 1,
  "choices": [
    {
      "finish_reason": "null",
      "delta": {
        "role": "assistant",
        "content": ""
      }
    }
  ]
  }''')
    response["choices"][0]["delta"]["content"] = ""
    jresponse = json.dumps(response)
    #self.wfile.write(bytes(f'data: {jresponse}','utf-8'))
    ores = runline2(ai, codequery).strip()
    print("============")
    print(ores)
    print("============")
    response["choices"][0]["delta"]["content"] = ores
    response["choices"][0]["finish_reason"] = "length"
    self.send_response(200)
    self.end_headers()
    jresponse = json.dumps(response)
    # print(jresponse)
    self.wfile.write(bytes(f'data: {jresponse}','utf-8'))
    print("computed")

def handle_api_show(self, ai, obj, runline2, method):
    print("/api/show")
    # receive {"prompt": ""}
    if obj == None or "name" not in obj:
        print("ObjNone")
        self.send_response(200)
        self.end_headers()
        return True
    mname = obj["name"]
    response = {
        "modelfile": "r2ai:latest",
        "parameters": "num_ctx                        4096\nstop                           \u003c/s\u003e\nstop                           USER:\nstop                           ASSISTANT:",
        "template": "{{ .System }}\nUSER: {{ .Prompt }}\nASSISTANT: ",
        "details": {
            "format": "gguf",
            "family": "llama",
            "families": ["llama", "clip"],
            "parameter_size": "7B",
            "quantization_level": "Q4_0"
        }
    }
    self.send_response(200)
    self.end_headers()
    jresponse = json.dumps(response)
    self.wfile.write(bytes(f'{jresponse}','utf-8'))

def handle_cmd(self, ai, obj, runline2, method):
    # receive {"prompt": ""}
    userline = self.path[5:].replace("%20", " ");
    print("RUNLINE: " + userline)
    ores = runline2(ai, userline)
    self.send_response(200)
    self.end_headers()
    self.wfile.write(bytes(f'{ores}','utf-8'))
    return True

def handle_v1_chat(self, ai, obj, runline2, method):
    print("/api/chat")
    # receive {"prompt": ""}
    if obj == None or "messages" not in obj:
        print("ObjNone")
        self.send_response(200)
        self.end_headers()
        return True
    messages = obj["messages"]
    codequery = ""
    for m in messages:
        if m["role"] == "user":
            codequery = m["content"] + "\n"
        else:
            codequery = m["role"] + ": " + m["content"]
    ores = runline2(ai, codequery.strip()).strip()
    response = {
        "model": "r2ai:latest",
        "created_at": get_timez(),
        "response": ores,
        "message": {
            "role": "assistant",
            "content": ores,
            "images": None
        },
        "done": True,
    }
    self.send_response(200)
    self.end_headers()
    jresponse = json.dumps(response)
    self.wfile.write(bytes(f'{jresponse}','utf-8'))

# like completions but in realtime
def handle_v1_chat_generate(self, ai, obj, runline2, method):
    print("/api/generate")
    if obj == None or "prompt" not in obj:
        print("ObjNone")
        self.send_response(200)
        self.end_headers()
        return True
    codequery = obj["prompt"]
    #runline2(ai, "-R")
    ores = runline2(ai, codequery).strip()
    response = {
        "model": "r2ai:latest",
        "created_at": get_timez(),
        "response": ores,
        "done": True,
        "done_reason": "stop"
    }
    self.send_response(200)
    self.end_headers()
    jresponse = json.dumps(response)
    self.wfile.write(bytes(f'{jresponse}','utf-8'))

def handle_v1_completions(self, ai, obj, runline2, method):
    global ores
    print("/v1/completions")
    if obj == None:
        print("ObjNone")
        self.send_response(200)
        self.end_headers()
        return True
    if "segments" not in obj:
        return handle_v1_completions_default(self, ai, obj, runline2, method)
    pfx = obj["segments"]["prefix"].strip()
    sfx = obj["segments"]["suffix"].strip()
    lng = obj["language"]
    if pfx == "":
        self.send_response(200)
        self.end_headers()
        return True
    #runline2(ai, "-R")
    #codequery = f"What's between `{pfx}` and `{sfx}` in `{lng}`, without including the context"
    codequery = f"Complete the code between `{pfx}` and `{sfx}` in `{lng}`"
    response = json.loads('''{
  "id": "cmpl-9d8aab26-ddc1-4314-a937-6654f2c13932",
  "choices": [
    {
      "index": 0,
      "text": ""
    }
  ]
  }''')
    print(f"PREFIX {pfx}")
    print(f"SUFFIX {sfx}")
    print(f"RES {ores}")
    response["choices"][0]["text"] = ores
    jresponse = json.dumps(response)
    self.send_response(200)
    self.end_headers()
    self.wfile.write(bytes(f'{jresponse}','utf-8'))
    print("compute query")
    ores = runline2(ai, codequery).strip()
    ores = ores.replace(pfx, "")
    ores = ores.replace(sfx, "")
    ores = re.sub(r'```.*$', '', ores)
    ores = ores.replace("```javascript", "")
    ores = ores.replace("```", "")
    ores = ores.replace("\n", "");
    ores = ores.strip()
    print(f"RES2 {ores}")
    print("computed")

def handle_tabby_query(self, ai, obj, runline2, method):
    global ores
    print(self.path)
    if self.path == '/api/generate':
        return handle_v1_chat_generate(self, ai, obj, runline2, method)
    if self.path == '/api/chat':
        return handle_v1_chat(self, ai, obj, runline2, method)
    if self.path == '/api/show':
        return handle_api_show(self, ai, obj, runline2, method)
    if self.path == '/api/tags':
        models = {
                "models":[
                    {
                        "name": "r2ai:latest",
                     "model": "r2ai:latest",
                     "modified_at":get_timez(),
                     "size":4661224676,
                     "digest":"365c0bd3c000a25d28ddbf732fe1c6add414de7275464c4e4d1c3b5fcb5d8ad1",
                     "details":{"parent_model":"","format":"gguf","family":"llama","families":["llama"],"parameter_size":"8.0B","quantization_level":"Q4_0"},
                     "expires_at":"0001-01-01T00:00:00Z"
                     }
                    ]
        }
        models=json.dumps(models)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(bytes(f'{models}','utf-8'))
        return True
    if self.path == "/v1/chat/completions":
        return handle_v1_chat_completions(self, ai, obj, runline2, method)
    if self.path == "/v1/health": ## GET only
        self.send_response(200)
        self.end_headers()
        # TODO build proper health json instead of copypasting a stolen one
        model = ai.env["llm.model"]
        healthobj = {
                "model":ai.env["llm.model"],
                "device":"gpu" if ai.env["llm.gpu"] else "cpu",
                "arch": platform.machine(),
                "cpu_info": "",
                "cpu_count": 1,
                "cuda_devices": [],
                "version": {
                    "build_date": "2024-05-22",
                    "build_timestamp": "2024-05-22",
                    "git_sha": "",
                    "git_describe": "",
                },
        }
        healthstr=json.dumps(healthobj)
        self.wfile.write(bytes(f'{healthstr}','utf-8'))
        return True
    if ai.env["http.tabby"] == "true":
        # /v1/completions
        if self.path == "/v1/completions":
            return handle_v1_completions(self, ai, obj, runline2, method)

    print(f"UnkPath: {self.path}")
    self.send_response(200)
    self.end_headers()
    self.wfile.write(bytes('{}\n','utf-8'))
    return True

def handle_custom_request(self, ai, msg, runline2, method):
    print("CUSTOM")
    if method == "GET":
        if self.path.startswith('/cmd'):
            return handle_cmd(self, ai, None, runline2, method)
        if handle_tabby_query(self, ai, None, runline2, method):
            return True
        return False
    if msg.startswith("{"):
        obj = json.loads(msg)
        #if "language" in obj:
        handle_tabby_query(self, ai, obj, runline2, method)
        return True
    return True

def start_http_server_now(ai, runline2):
    import http.server
    import socketserver
    WANTCTX = ai.env["http.chatctx"] == "true"
    PORT = int(ai.env["http.port"])
    BASEPATH = ai.env["http.path"]
    Handler = http.server.SimpleHTTPRequestHandler
    class SimpleHTTPRequestHandler(Handler):
        def do_GET(self):
            print("GET")
            if handle_custom_request(self, ai, "", runline2, "GET"):
                return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(bytes(f'Invalid request. Use POST and /{BASEPATH}', 'utf-8'))
        def do_POST(self):
            print("POST")
            if not WANTCTX:
                runline2(ai, "-R")
            content_length = int(self.headers['Content-Length'])
            msg = self.rfile.read(content_length).decode('utf-8')
            if handle_custom_request(self, ai, msg, runline2, "POST"):
                return
            if self.path.startswith(BASEPATH):
                self.send_response(200)
                self.end_headers()
                res = runline2(ai, msg)
                self.wfile.write(bytes(f'{res}','utf-8'))
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(bytes(f'Invalid request. Use {BASEPATH}'))
    LOGGER.getChild("server").info("[R2AI] Serving at port %s", PORT)
    Handler.protocol_version = "HTTP/1.0"
    global server
    server = socketserver.TCPServer(("", PORT), SimpleHTTPRequestHandler)
    server.allow_reuse_address = True
    server.allow_reuse_port = True
    server.serve_forever()

def start_http_server(ai, runline2, background):
    global server_thread
    server_thread = Thread(target=start_http_server_now, args=(ai, runline2))
    server_thread.start()
    if not background:
        global kill_event
        kill_event = Event()
        while not kill_event.is_set():
            time.sleep(1)
        kill_event = None

def stop_http_server(force=False):
    if not force and server_in_background():
        return
    LOGGER.getChild("server").info("Stopping server")
    global server
    if server:
        _kill_server()
        server = None
    global server_thread
    if server_thread:
        server_thread.join()
        server_thread = None
    if not server_in_background():
        kill_event.set()

def server_running():
    global server_thread
    global server
    return bool(server) and bool(server_thread)

def server_in_background():
    global kill_event
    return server_running and not bool(kill_event)

def _kill_server():
    global server
    server.shutdown()
    Thread(target=server.server_close).start()
