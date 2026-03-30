import { state } from "./state";
import { fileDump, tmpdir } from "./utils";
import { callProvider } from "./providers";
import { httpGet } from "./http";

export function r2ai(
  queryText: string,
  fileData: string | null,
  hideprompt: boolean = false,
): string {
  const cleanFileData = (fileData || "").replace(/`/g, "");
  const cleanQuery = queryText.replace(/'/g, "");

  // Handle r2ai server mode
  if (state.api === "r2" || state.api === "r2ai") {
    const fileName = tmpdir(".pdc.txt");
    fileDump(fileName, cleanFileData);

    const q = cleanQuery.startsWith("-")
      ? cleanQuery
      : ["-i", fileName, cleanQuery].join(" ");

    const host = state.baseurl
      ? state.baseurl + "/cmd"
      : state.host + ":" + state.port + "/cmd";

    const url = host + "/" + encodeURIComponent(q);
    const response = httpGet(url, []);
    if (response.error) {
      return `Error: ${response.error}`;
    }
    return response.result || JSON.stringify(response) ||
      "Cannot curl, use r2ai-server or r2ai -w";
  }

  if (cleanQuery.startsWith("-")) return "";

  let q = cleanQuery + ":\n" + cleanFileData;
  if (state.maxInputTokens > 0 && q.length > state.maxInputTokens) {
    q = q.slice(0, state.maxInputTokens);
  }

  return callProvider(q, hideprompt);
}
