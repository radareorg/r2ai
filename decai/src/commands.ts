import { AutoReply } from "./types";
import { state } from "./state";
import { VERSION, COMMAND, DEFAULT_PROMPT, HELP_TEXT } from "./constants";
import { b64, trimAnsi, trimDown, trimJson, filterResponse, debugLog } from "./utils";
import { listApiKeys, editApiKeys } from "./apiKeys";
import { evalConfig, listAllConfig } from "./config";
import { r2ai } from "./r2ai";

export function showHelp(): void {
  let helpmsg = "";
  const msg = (m: string) => (helpmsg += " " + COMMAND + " " + m + "\n");

  helpmsg += "Usage: " + COMMAND + " (-h) ...\n";
  helpmsg += "Version: " + VERSION + "\n";
  msg("-a [query]    - solve query with auto mode");
  msg("-b [url]      - set base URL (alias for decai -e baseurl)");
  msg("-d [f1 ..]    - decompile given functions");
  msg("-dd [..]      - same as above, but ignoring cache");
  msg("-dD [query]   - decompile current function with given extra query");
  msg("-dr           - decompile function and its called ones (recursive)");
  msg("-e            - display and change eval config vars");
  msg("-h            - show this help");
  msg("-H            - help setting up r2ai");
  msg("-i [f] [q]    - include given file and query");
  msg("-k            - list API key status");
  msg("-K            - edit apikeys.txt");
  msg("-m [model]    - use -m? or -e model=? to list the available models");
  msg("-n            - suggest better function name");
  msg("-p [provider] - same as decai -e api (will be provider)");
  msg("-q [text]     - query language model with given text");
  msg("-Q [text]     - query on top of the last output");
  msg("-r [prompt]   - change role prompt (same as: decai -e prompt)");
  msg("-R            - reset role prompt to default prompt");
  msg("-s            - function signature");
  msg("-v            - show local variables");
  msg("-V            - find vulnerabilities");
  msg("-x[*]         - eXplain current function (-x* for r2 script)");

  r2.log(helpmsg.trim());
}

export function decompile(
  args: string,
  extraQuery: boolean,
  useCache: boolean,
  recursiveCalls: boolean
): string | undefined {
  if (useCache) {
    const cachedAnnotation = r2.cmd("anos").trim();
    if (cachedAnnotation.length > 0) {
      return cachedAnnotation;
    }
  }

  let context = "";
  if (recursiveCalls) {
    const at = r2.cmd("s");
    context += "## Context functions:\n";
    const funcs = r2.cmdAt("axff~^C[2]~$$", at);
    for (const addr of funcs.split(/\n/g)) {
      context += r2.cmd("pdc@" + addr);
    }
    r2.cmd("s " + at);
  }

  const appendQuery = extraQuery ? " " + args : "";
  const origColor = r2.cmd("e scr.color");

  try {
    const parsedArgs = args.slice(2).trim();
    let count = 0;
    let text = "";

    if (
      state.contextFile !== "" &&
      r2.cmd2("test -f " + state.contextFile).value === 0
    ) {
      text +=
        "## Context:\n[START]\n" +
        r2.cmd("cat " + state.contextFile) +
        "\n[END]\n";
    }

    r2.cmd("e scr.color=0");
    let body = "## Before:\n";

    for (const c of state.commands.split(",")) {
      if (c.trim() === "") continue;

      const oneliner =
        extraQuery || parsedArgs.trim().length === 0
          ? c
          : c + "@@= " + parsedArgs;
      const output = r2.cmd(oneliner);

      if (output.length > 5) {
        body += "Output of " + c + ":\n[START]\n" + output + "\n[END]\n";
        count++;
      }
    }

    body += "## After:\n";
    r2.cmd("e scr.color=" + origColor);

    if (count === 0) {
      console.error("Nothing to do.");
      return;
    }

    let out = "";
    if (state.decopipe.use) {
      const dpipe = state.decopipe[state.decopipe.default as string] as {
        pipeline: Array<{ model?: string; query: string }>;
        globalQuery: string;
      };
      const origModel = state.model;
      let code = text + body;

      for (const dp of dpipe.pipeline) {
        if (dp.model) state.model = dp.model;
        const query = dp.query + ". " + dpipe.globalQuery;
        out = r2ai(query, code, true);
        if (state.debug) {
          console.log("QUERY\n", query, "\nINPUT\n", code, "\nOUTPUT\n", out);
        }
        code = out;
      }
      out = code;
      state.model = origModel;
    } else {
      const query = appendQuery;
      text += body + context;
      out = r2ai(query, text, false);
      state.lastOutput = out;
    }

    if (useCache && out.length > 1) {
      r2.call("ano=base64:" + b64(out));
    }

    if (out.startsWith("```")) {
      out = out.replace(/```.*\n/, "").replace(/```$/, "");
    }

    return out.trim();
  } catch (e) {
    r2.cmd("e scr.color=" + origColor);
    const err = e as Error;
    console.error(err, err.stack);
    return;
  }
}

export function explainFunction(): string {
  const origColor = r2.cmd("e scr.color");
  r2.cmd("e scr.color=0");
  const hints =
    "[START]" + state.commands.split(",").map((c) => r2.cmd(c)).join("\n") + "[END]";
  r2.cmd("e scr.color=" + origColor);

  const res = r2ai(
    "Analyze function calls, references, comments and strings, loops and ignore registers and memory accesses. Explain the purpose of this function in a single short sentence. /no_think Do not introduce or argue the response, translation of the explanation in " +
      state.humanLanguage,
    hints,
    true
  );

  const lines = res.trim().split(/\n/g);
  return lines[lines.length - 1].trim();
}

export function suggestSignature(): string {
  const tmp = state.language;
  const code = r2.cmd("afv;pdc");
  state.language = "C";

  let out =
    "'afs " +
    r2ai(
      "analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the return. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",
      code,
      false
    );

  const brace = out.indexOf("{");
  if (brace !== -1) {
    out = out.substring(0, brace);
  }

  state.language = tmp;
  return out;
}

export function autoMode(queryText: string, mainHandler: (args: string) => boolean): void {
  const replies: string[] = [];

  while (true) {
    let q = HELP_TEXT.auto;

    if (replies.length > 0) {
      q += "## Command Results\n\n";
      for (const rep of replies) {
        const rp = JSON.parse(rep);
        q += "### " + rp.command + "\n\n```\n" + rp.response + "\n```\n";
      }
    }

    q += "\n\n## User Prompt\n\n" + queryText;

    if (state.debug) {
      console.log("#### input\n", q, "\n#### /input");
    }

    console.log("Thinking...");
    const out = r2ai("", q, true);

    if (state.debug) {
      console.log("#### output\n", out, "\n#### /output");
    }

    try {
      const o: AutoReply = JSON.parse(
        trimJson(trimDown(filterResponse(out)))
      );

      if (
        o.action === "r2cmd" ||
        o.action === "response" ||
        o.action === o.command
      ) {
        const ocmd = o.command || "";

        if (o.reason) {
          console.log("[r2cmd] Reasoning: " + o.reason);
          if (state.tts) {
            r2.syscmd("pkill say");
            r2.syscmd(
              "say -v Alex -r 250 '" + o.reason.replace(/'/g, "") + "' &"
            );
          }
        }

        console.log("[r2cmd] Action: " + o.description);
        console.log("[r2cmd] Command: " + ocmd);

        let cmd = ocmd;
        if (!state.yolo) {
          cmd = autoRepl(ocmd, mainHandler);
        }

        console.log("[r2cmd] Running: " + cmd);
        const obj = r2.cmd2(cmd);
        const logs = obj.logs
          ? obj.logs.map((x: { type: string; message: string }) => x.type + ": " + x.message).join("\n")
          : "";
        const res = (obj.res + logs).trim();

        console.log(res);
        const cleanRes = trimAnsi(res);

        if (state.debug) {
          console.log("<r2output>\n", cleanRes, "\n<(r2output>");
        }

        replies.push(
          JSON.stringify({
            action: "response",
            command: cmd,
            description: o.description,
            response: cleanRes,
          })
        );
      } else if (o.action === "reply") {
        console.log("Done\n", o.response);
        break;
      } else {
        console.log("Unknown response\n", JSON.stringify(out));
      }
    } catch (e) {
      const response = out.indexOf('response": "');
      if (response !== -1) {
        const res = out
          .slice(response + 12)
          .replace(/\\n/g, "\n")
          .replace(/\\/g, "");
        console.log(res);
      } else {
        console.log(out);
        console.error(e);
      }
      break;
    }
  }
}

function autoRepl(ocmd: string, mainHandler: (args: string) => boolean): string {
  while (true) {
    const cmd = r2.cmd("'?ie Tweak command? ('?' for help)").trim();

    if (cmd === "q!") {
      console.error("Break!");
      break;
    }
    if (cmd === "?") {
      autoHelp();
      continue;
    } else if (cmd.startsWith(":")) {
      console.log(r2.cmd(cmd.slice(1)));
      continue;
    } else if (cmd.startsWith("-e")) {
      mainHandler(cmd);
      continue;
    } else if (cmd === "!") {
      return "?e do NOT execute '" + ocmd + "' again, continue without it";
    } else if (cmd.startsWith("!")) {
      console.log(r2.syscmd(cmd.slice(1)));
      continue;
    } else if (cmd === "q") {
      return "?e All data collected!. Do not call more commands, reply the solutions";
    } else if (!cmd) {
      return ocmd;
    } else {
      const comment = cmd.indexOf("#");
      if (comment !== -1) {
        const command = cmd.slice(0, comment).trim();
        return command;
      }
      return cmd;
    }
  }
  return ocmd;
}

function autoHelp(): void {
  console.log(" '!'     do not run this command");
  console.log(" '!c'    run system command");
  console.log(" 'q'     to quit auto and try to solve");
  console.log(" 'q!'    quit auto without solving");
  console.log(" 'c # C' use given command with comment");
  console.log(" ':c'    run r2 command without feeding auto");
  console.log(" '-e'    set decai configuration variables");
}

export function handleCommand(args: string, mainHandler: (args: string) => boolean): string | undefined {
  if (args === "" || !args.startsWith("-")) {
    showHelp();
    return;
  }

  let output = "";
  const flag = args[1];

  switch (flag) {
    case "H":
      console.log(HELP_TEXT.decai);
      break;

    case "a":
      autoMode(args.slice(2).trim(), mainHandler);
      break;

    case "m": {
      const arg0 = args.slice(2).trim();
      if (arg0 === "=") {
        evalConfig("model=");
      } else if (arg0) {
        evalConfig("model=" + arg0);
      } else {
        evalConfig("model");
      }
      break;
    }

    case "n":
    case "f": {
      output = r2.cmd("axff~$[3]");
      const considerations = r2
        .cmd("fd.")
        .trim()
        .split(/\n/)
        .filter((x: string) => !x.startsWith("secti"))
        .join(",");

      output = r2ai(
        "give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: " +
          considerations,
        output,
        false
      ).trim();
      output += " @ " + r2.cmd("?v $FB").trim();
      break;
    }

    case "v":
      output = r2.cmd("afv;pdc");
      output = r2ai(
        "guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",
        output,
        false
      );
      break;

    case "i": {
      const parts = args.slice(2).trim().split(/ /g);
      if (parts.length >= 2) {
        const file = parts[0];
        const query = parts.slice(1).join(" ");
        const fileData = r2.cmd("cat " + file);
        console.log(r2ai(query, fileData, true));
      } else {
        console.log("Use: decai -i [file] [query ...]");
      }
      break;
    }

    case "p": {
      const evalArg = args.slice(2).trim();
      if (evalArg) {
        evalConfig("api=" + evalArg);
      } else {
        listApiKeys();
      }
      break;
    }

    case "r": {
      const prompt = args.slice(2).trim();
      if (prompt) {
        state.prompt = prompt;
      } else {
        console.log(state.prompt);
      }
      break;
    }

    case "R":
      state.prompt = DEFAULT_PROMPT;
      break;

    case "s":
      output = suggestSignature();
      break;

    case "V":
      output = r2ai(
        "find vulnerabilities, dont show the code, only show the response, provide a sample exploit",
        state.lastOutput,
        false
      );
      break;

    case "K":
      editApiKeys();
      break;

    case "k":
      listApiKeys();
      break;

    case "b": {
      const baseUrlArg = args.slice(2).trim();
      if (baseUrlArg) {
        evalConfig("baseurl=" + baseUrlArg);
      } else {
        console.log(state.baseurl);
      }
      break;
    }

    case "e": {
      const evalArg = args.slice(2).trim();
      if (evalArg) {
        evalConfig(evalArg);
      } else {
        listAllConfig();
      }
      break;
    }

    case "q":
      try {
        output = r2ai(args.slice(2).trim(), null, true);
      } catch (e) {
        const err = e as Error;
        console.error(err, err.stack);
      }
      break;

    case "Q":
      output = r2ai(args.slice(2).trim(), state.lastOutput, false);
      break;

    case "x":
      output = explainFunction();
      if (args[2] === "*" || args[2] === "r") {
        output = "'CC " + output;
      }
      break;

    case "d":
      if (args[2] === "r") {
        output = decompile(args.slice(2), true, state.cache, true) || "";
      } else if (args[2] === "d") {
        output = decompile(args, false, false, false) || "";
      } else if (args[2] === "D") {
        output = decompile(args, true, false, false) || "";
      } else {
        output = decompile(args, false, state.cache, false) || "";
      }
      break;

    default:
      showHelp();
      break;
  }

  return output || undefined;
}
