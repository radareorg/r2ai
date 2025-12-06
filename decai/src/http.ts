import { HttpResponse } from "./types";
import { state } from "./state";
import { debugLog } from "./utils";

interface HttpRequestOptions {
  method: "GET" | "POST";
  url: string;
  headers: string[];
  payload?: string;
}

function executeCurl(options: HttpRequestOptions): string {
  const { method, url, headers, payload } = options;
  const cmdParts = ["curl", "-s", url];
  headers.forEach((h) => cmdParts.push("-H", `"${h}"`));
  cmdParts.push("-H", '"Content-Type: application/json"');

  if (method === "POST") {
    if (!payload) throw new Error("Payload required for POST requests");
    const tmpfile = r2.fdump(payload);
    cmdParts.push("-d", `'@${tmpfile}'`);
    const cmd = cmdParts.join(" ") + " && rm " + tmpfile;
    debugLog(cmd);
    return r2.syscmds(cmd);
  } else {
    const cmd = cmdParts.join(" ");
    debugLog(cmd);
    return r2.syscmds(cmd);
  }
}

function parseJson(output: string): any {
  if (output === "") {
    throw new Error("empty response");
  }
  try {
    return JSON.parse(output);
  } catch (e) {
    const err = e as Error;
    console.error("output:", output);
    console.error(err, err.stack);
    throw new Error(err.message || "JSON parse error");
  }
}

export function httpRequest(options: HttpRequestOptions): HttpResponse {
  try {
    const output = executeCurl(options);
    try {
      return parseJson(output);
    } catch (e) {
      return { error: (e as Error).message };
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
