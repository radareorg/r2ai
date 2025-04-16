// proxy_server.ts
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

import VectorDB from "./vdb.ts"

const CONTEXT_SIZE = 5;
const VECTOR_DIMENSION = 64;
const TARGET_SERVER = "http://localhost:11434"; // 👈 change to your target
const DATA_PATH = "../doc/data/quotes.txt";

function isIntercepted(url: string) {
  return url.startsWith("/api/chat");
}

const db = new VectorDB(VECTOR_DIMENSION);
const fileContent = await Deno.readTextFile(DATA_PATH);
const lines = fileContent.split("\n");
for (const line of lines) {
	if (line.trim().length > 0) {
  db.insert(line);
  // console.log("Line:", line);
	}
}

serve(async (req) => {
  const url = new URL(req.url);
  const targetUrl = new URL(url.pathname + url.search, TARGET_SERVER);
  console.log(req);

  let body = req.body;
  if (req.method === "POST" && req.url.endsWith("/api/chat")) {
    const obj = JSON.parse(await req.text());
    const newMessages = [];
    for (let msg of obj.messages) {
      let content = "<prompt>" + msg.content.trim() + "</prompt>\n";
      if (msg.role === "user") {
          const context = db.query(msg.content, CONTEXT_SIZE);
	  for (const ctx of context) {
            console.log("<context>" + ctx);
            content += "<context>" + ctx + "</context>\n";
	  }
      }
      console.log(content);
      msg.content = content;
      newMessages.push(msg);
    }
    obj.messages = newMessages;
    body = JSON.stringify(obj);
  }

  const proxyReq = new Request(targetUrl.toString(), {
    method: req.method,
    headers: req.headers,
    body: body,
    redirect: "manual",
  });

  try {
    const response = await fetch(proxyReq);
    const responseBody = response.body;
    const responseHeaders = new Headers(response.headers);
    return new Response(responseBody, {
      status: response.status,
      headers: responseHeaders,
    });
  } catch (err) {
    console.error("Proxy error:", err);
    return new Response("Proxy error", { status: 502 });
  }
}, { port: 8000 });
