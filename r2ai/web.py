def start_http_server(ai, runline2):
  import http.server
  import socketserver

  WANTCTX = ai.env["http.chatctx"] == "true"
  PORT = int(ai.env["http.port"])
  BASEPATH = ai.env["http.path"]

  Handler = http.server.SimpleHTTPRequestHandler

  class SimpleHTTPRequestHandler(Handler):
    def do_GET(self):
      self.send_response(404)
      self.end_headers()
      self.wfile.write(bytes(f'Invalid request. Use POST and /{BASEPATH}', 'utf-8'))
    def do_POST(self):
      if self.path.startswith(BASEPATH):
        content_length = int(self.headers['Content-Length'])
        msg = self.rfile.read(content_length).decode('utf-8')
        self.send_response(200)
        self.end_headers()
        if WANTCTX:
          runline2(ai, "-R")
        res = runline2(ai, msg)
        self.wfile.write(bytes(f'{res}','utf-8'))
      else:
        self.send_response(404)
        self.end_headers()
        self.wfile.write(bytes(f'Invalid request. Use {BASEPATH}'))

  print("[r2ai] Serving at port", PORT)
  Handler.protocol_version = "HTTP/1.0"
  server = socketserver.TCPServer(("", PORT), SimpleHTTPRequestHandler)
  server.allow_reuse_address = True
  server.allow_reuse_port = True
  server.serve_forever()

