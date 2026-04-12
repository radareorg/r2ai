import { HttpResponse } from "./types";
import { state } from "./state";
import { mergeHeaders } from "./headers";
import { debugLog } from "./utils";

interface HttpRequestOptions {
  method: "GET" | "POST";
  url: string;
  headers: string[];
  payload?: string;
}

function shellEscape(arg: string): string {
  return `'${arg.replace(/'/g, `'"'"'`)}'`;
}

function executeCurl(options: HttpRequestOptions): string {
  const { method, url, headers, payload } = options;
  const cmdParts = ["curl", "-s"];
  if (state.timeout > 0) {
    cmdParts.push("--max-time", String(state.timeout));
  }
  const requestHeaders = mergeHeaders(
    ["Content-Type: application/json"],
    headers,
  );
  requestHeaders.forEach((h) => cmdParts.push("-H", shellEscape(h)));

  if (method === "POST") {
    if (!payload) throw new Error("Payload required for POST requests");
    const tmpfile = r2.fdump(payload);
    cmdParts.push("--data-binary", "@" + shellEscape(tmpfile), shellEscape(url));
    const cmd = cmdParts.join(" ") + "; rm " + shellEscape(tmpfile);
    debugLog(cmd);
    return r2.syscmds(cmd);
  } else {
    cmdParts.push(shellEscape(url));
    const cmd = cmdParts.join(" ");
    debugLog(cmd);
    return r2.syscmds(cmd);
  }
}

function parseNdjson(output: string): HttpResponse | null {
  const lines = output.split("\n").filter((l) => l.trim() !== "");
  if (lines.length <= 1) return null;

  let content = "";
  let lastObj: Record<string, unknown> | null = null;

  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      if (obj.error) return obj as HttpResponse;
      if (obj.message?.content !== undefined) {
        content += obj.message.content;
      }
      lastObj = obj;
    } catch {
      return null;
    }
  }

  if (lastObj) {
    lastObj.message = { role: "assistant", content };
    return lastObj as HttpResponse;
  }
  return null;
}

export function httpRequest(options: HttpRequestOptions): HttpResponse {
  try {
    const output = executeCurl(options).trim();
    if (output === "") {
      return { error: "empty response" };
    }
    try {
      return JSON.parse(output) as HttpResponse;
    } catch {
      const ndjson = parseNdjson(output);
      if (ndjson) return ndjson;
      return { error: output, rawOutput: output };
    }
  } catch (e) {
    const err = e as Error;
    return { error: err.message };
  }
}

export function httpGet(url: string, headers: string[]): HttpResponse {
  return httpRequest({ method: "GET", url, headers });
}

export function httpPost(
  url: string,
  headers: string[],
  payload: string,
): HttpResponse {
  return httpRequest({ method: "POST", url, headers, payload });
}
