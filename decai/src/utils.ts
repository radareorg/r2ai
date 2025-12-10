import { state } from "./state";

export function tmpdir(path: string): string {
  const dir = r2.cmd("-e dir.tmp").trim() ?? ".";
  return dir + "/" + path;
}

export function fileExists(path: string): boolean {
  if (r2.cmd2("test -h").logs[0].message.indexOf("-fdx") !== -1) {
    return true; // r2 is old
  }
  return r2.cmd("'test -vf " + path).startsWith("found");
}

export function padRight(str: string, length: number): string {
  return str + " ".repeat(Math.max(0, length - str.length));
}

export function trimAnsi(str: string): string {
  return str.replace(/\x1b\[[0-9;]*m/g, "");
}

export function trimDown(out: string): string {
  const jsonMatch = out.match(/```json\s*([\s\S]*?)```/);
  return jsonMatch && jsonMatch[1] ? jsonMatch[1].trim() : out;
}

export function trimJson(out: string): string {
  let result = out;
  const bob = result.indexOf("{");
  if (bob !== -1) result = result.slice(bob);
  const eob = result.indexOf("}");
  if (eob !== -1) result = result.slice(0, eob + 1);
  return result;
}

export function b64(str: string): string {
  return btoa(str);
}

export function fileDump(fileName: string, fileData: string): void {
  const d = b64(fileData);
  r2.cmd("p6ds " + d + " > " + fileName);
}

export function filterResponse(msg: string): string {
  let result = msg;
  if (state.think !== 2) {
    result = result.replace(/<think>[\s\S]*?<\/think>/gi, "");
  }
  return result
    .split("\n")
    .filter((line) => !line.trim().startsWith("```"))
    .join("\n");
}

export function debugLog(msg: string): void {
  if (state.debug) {
    console.log(msg);
  }
}

export function parseEnvLikeString(input: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of input.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const [key, ...rest] = trimmed.split("=");
    if (!key || rest.length === 0) {
      continue;
    }
    const value = rest.join("=").trim();
    // Normalize key: strip trailing _API_KEY (case-insensitive)
    const normKey = key.toLowerCase().replace(/_api_key$/i, "");
    result[normKey] = value;
  }
  return result;
}
