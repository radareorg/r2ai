import { HttpResponse } from "./types";
import { state } from "./state";
import { debugLog } from "./utils";

export function httpGet(url: string, headers: string[]): HttpResponse {
  const heads = headers.map((x) => `-H "${x}"`).join(" ");
  const cmd = `curl -s ${url} ${heads} -H "Content-Type: application/json"`;
  return JSON.parse(r2.syscmds(cmd));
}

export function httpPost(url: string, headers: string[], payload: string): HttpResponse {
  const heads = headers.map((x) => `-H "${x}"`).join(" ");

  const curlArgs = (url: string, heads: string, payload: string): string => {
    const escapedPayload = payload.replace(/'/g, "'\\''");
    const cmd = `curl -s '${url}' ${heads} -d '${escapedPayload}' -H "Content-Type: application/json"`;
    debugLog(cmd);
    return r2.syscmds(cmd);
  };

  const curlFile = (url: string, heads: string, payload: string): string => {
    const tmpfile = r2.fdump(payload);
    const cmd = `curl -s '${url}' ${heads} -d '@${tmpfile}' -H "Content-Type: application/json"`;
    debugLog(cmd);
    const output = r2.syscmd(cmd);
    r2.syscmd("rm " + tmpfile);
    return output;
  };

  const method = state.useFiles ? curlFile : curlArgs;
  const output = method(url, heads, payload);

  if (output === "") {
    return { error: "empty response" };
  }

  try {
    return JSON.parse(output);
  } catch (e) {
    const err = e as Error;
    console.error("output:", output);
    console.error(err, err.stack);
    return { error: err.stack };
  }
}
