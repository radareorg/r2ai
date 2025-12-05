import { state } from "./state";
import { tmpdir, fileDump, debugLog } from "./utils";
import { callProvider } from "./providers";

export function r2ai(queryText: string, fileData: string | null, hideprompt: boolean = false): string {
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

    const ss = q.replace(/ /g, "%20").replace(/'/g, "\\'");
    const cmd =
      'curl -s "' +
      host +
      "/" +
      ss +
      '" || echo "Cannot curl, use r2ai-server or r2ai -w"';

    debugLog(cmd);
    return r2.syscmds(cmd);
  }

  if (cleanQuery.startsWith("-")) return "";

  let q = cleanQuery + ":\n" + cleanFileData;
  if (state.maxInputTokens > 0 && q.length > state.maxInputTokens) {
    q = q.slice(0, state.maxInputTokens);
  }

  return callProvider(q, hideprompt);
}
