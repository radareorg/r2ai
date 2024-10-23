(function () {
    const decaiHelp = `
# Using Decai

You must run an r2ai-server in local or connect to a remote backend via api:

## Local backends:

### R2AI

Run 'decai -e api=r2ai' inside r2. Optimized for 'r2ai -w' as backend (see below)

### OpenAPI

You can use ollama, llamacpp, r2ai-server, etc

It connects to decai -e host/port via OpenAPI rest endpoints.

### Setting up r2ai-server:

Install r2ai or r2ai-server with r2pm:

    r2pm -ci r2ai

Choose one of the recommended models (after r2pm -r r2ai):

    * -m ibm-granite/granite-20b-code-instruct-8k-GGUF
    * -m QuantFactory/granite-8b-code-instruct-4k-GGUF
    * -m TheBloke/Mistral-7B-Instruct-v0.2-GGUF

Start the webserver:

   $ r2pm -r r2ai
   $ echo $CLAUDEAPIKEY > ~/.r2ai.anthropic
   [r2ai:0x0000000]> -m anthropic:claude-3-5-sonnet-20241022
   [r2ai:0x0000000]> -w
   Webserver listening at port 8080

You can also make r2ai -w talk to an 'r2ai-server' using this line:

  [r2ai:0x0000000]> -m openapi:http://localhost:8080
  [r2ai:0x0000000]> -e http.port=8082

  [0x0000000]> decai -e host=http://localhost:8082
## Remote backends:

Specify the service to use:
  * decai -e api=openai
  * decai -e api=claude
  * decai -e api=hf

Write the API keys in corresponding files:

  * ~/.r2ai.openai-key
  * ~/.r2ai.huggingface-key
  * ~/.r2ai.anthropic-key

## Make those changes permanent

You can write your custom decai commands in your ~/.radare2rc file.

`;
    const command = "decai";
    let decaiHost = "http://localhost";
    let decaiPort = "8080";
    let decaiApi = "r2"; // uses /cmd endpoint
    let decaiCommands = "pdc";
    let decaiLanguage = "C";
    let decaiHumanLanguage = "English";
    let decaiDebug = false;
    let decaiContextFile = "";
    let decaiModel = "";
    let lastOutput = "";
    let decaiCache = false;
    // let decprompt = "Do not explain, respond using ONLY code. Simplify and make it more readable. Use better variable names, keep it simple and avoid unnecessary logic, rewrite 'goto' into higher level constructs, Use comments like 'string:' to resolve function call arguments";
    let decprompt = "Rewrite this function and respond ONLY with code, NO explanations, NO markdown, Change 'goto' into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and and strings from comments like 'string:'";

    function decaiEval(arg) {
        const [k, v] = arg.split("=");
        if (!v) {
            switch (k) {
            case "model":
                console.log(decaiModel);
                break;
            case "debug":
                console.log(decaiDebug);
                break;
            case "api":
                console.log(decaiApi);
                break;
            case "hlang":
                console.log(decaiHumanLanguage);
                break;
            case "lang":
                console.log(decaiLanguage);
                break;
            case "cache":
                console.log(decaiCache);
                break;
            case "cmds":
                console.log(decaiCommands);
                break;
            case "prompt":
                console.log(decprompt);
                break;
            case "ctxfile":
                console.log(decaiContextFile);
                break;
            case "host":
                console.log(decaiHost);
                break;
            case "port":
                console.log(decaiPort);
                break;
            default:
                console.error("Unknown key");
                break;
            }
            return;
        }
        switch (k) {
        case "debug":
            decaiDebug = (v === "true" || v === "1");
            break;
        case "api":
            if (v === "?") {
                console.error("r2ai\nclaude\nopenapi\nopenai\nhf");
            } else {
                decaiApi = v;
            }
            break;
        case "model":
            decaiModel = v;
            break;
        case "cache":
            decaiCache = v === "true" || v == 1;
            break;
        case "ctxfile":
            decaiContextFile = v;
            break;
        case "hlang":
            decaiHumanLanguage = v;
            break;
        case "lang":
            decaiLanguage = v;
            break;
        case "cmds":
            decaiCommands = v;
            break;
        case "prompt":
            decprompt = v;
            break;
        case "host":
            decaiHost = v;
            break;
        case "port":
            decaiPort = v;
            break;
        default:
            console.error("Unknown key");
            break;
        }
    }
    function usage() {
        console.error("Usage: " + command + " (-h) ...");
        console.error(" " + command + " -H         - help setting up r2ai");
        console.error(" " + command + " -d [f1 ..] - decompile given functions");
        console.error(" " + command + " -dd [..]   - same as above, but ignoring cache");
        console.error(" " + command + " -D [query] - decompile current function with given extra query");
        console.error(" " + command + " -e         - display and change eval config vars");
        console.error(" " + command + " -h         - show this help");
        console.error(" " + command + " -i [f] [q] - include given file and query");
        console.error(" " + command + " -n         - suggest better function name");
        console.error(" " + command + " -q [text]  - query language model with given text");
        console.error(" " + command + " -Q [text]  - query on top of the last output");
        console.error(" " + command + " -r         - change role prompt (same as: decai -e prompt)");
        console.error(" " + command + " -v         - show local variables");
        console.error(" " + command + " -V         - find vulnerabilities");
        console.error(" " + command + " -x         - eXplain current function");
    }
    function r2aiAnthropic(msg, hideprompt) {
       const claudeKey = r2.cmd("'cat ~/.r2ai.anthropic-key").trim()
       const claudeModel = (decaiModel.length > 0)? decaiModel: "claude-3-5-sonnet-20241022";
       if (claudeKey === '') {
           return "Cannot read ~/.r2ai.anthropic-key";
       }
       const payload = JSON.stringify({
           model: claudeModel,
           max_tokens: 5128,
           messages: [
               {
                   "role": "user",
                   "content": hideprompt ? msg
                     : decprompt + ", Rewrite this pseudocode into " + decaiLanguage + "\n" + msg
               }
           ]
       });
       const curlcmd = `curl -s https://api.anthropic.com/v1/messages
          -H "Content-Type: application/json"
          -H "anthropic-version: 2023-06-01"
          -H "x-api-key: ${claudeKey}"
          -d '${payload}'`.replace(/\n/g, "");
        if (decaiDebug) {
            console.error(curlcmd);
        }
        const res = r2.syscmds(curlcmd);
        if (decaiDebug) {
            console.error(res);
        }
        try {
            return JSON.parse(res).content[0].text;
        } catch(e) {
            console.error("ERROR: " + e + "(" + res + ")");
        }
        return "error invalid response";
    }
    function r2aiHuggingFace(msg, hideprompt) {
        const hfKey = r2.cmd("'cat ~/.r2ai.huggingface-key").trim();
        if (hfKey === '') {
            return "ERROR: Cannot read ~/.r2ai.huggingface-key";
        }
        let hfModel = "deepseek-ai/DeepSeek-Coder-V2-Instruct";
        if (decaiModel.length > 0) {
            hfModel = decaiModel;
	}
        // const hfModel = "instructlab/granite-7b-lab"
        // const hfModel = "TheBloke/Llama-2-7B-GGML"
        // const hfModel = "meta-llama/Llama-3.1-8B-Instruct";
        // const hfModel = "meta-llama/Llama-3.2-1B-Instruct";
        // const hfModel = "Qwen/Qwen2.5-72B-Instruct";
        const query = hideprompt? msg: decprompt + ", Output in " + decaiLanguage + " language\n" + msg;
        const payload = JSON.stringify({
            inputs: query,
            parameters: {
                max_new_tokens: 5128
            }
        });
        const curlcmd = `curl -s https://api-inference.huggingface.co/models/${hfModel}
            -H "Authorization: Bearer ${hfKey}"
            -H "Content-Type: application/json"
            -d '${payload}'`.replace(/\n/g, "");
        //if (decaiDebug) {
        //     console.log(curlcmd);
        //}

        const res = r2.syscmds(curlcmd);
        // Debug response instead of request
        if (decaiDebug) {
            console.log(res)
        }

        try {
            const o = JSON.parse(res);
            if (o.error) {
                return "ERROR: " + o.error;
            }
            return JSON.parse(res).generated_text;
        } catch (e) {
            console.error(e);
            console.log(res);
        }
        return "error invalid response";
    }

    function r2aiOpenAI(msg, hideprompt) {
       const openaiKey = r2.cmd("'cat ~/.r2ai.openai-key").trim()
       if (openaiKey === '') {
           return "Cannot read ~/.r2ai.openai-key";
       }
       const openaiModel = (decaiModel.length > 0)? decaiModel: "gpt-4";
       const query = hideprompt? msg: decprompt + ", Output in " + decaiLanguage + " language\n" + msg;
       const payload = JSON.stringify({
           model: openaiModel,
           max_tokens: 5128,
           messages: [
               // { "role": "system", "content": hideprompt? decprompt: "" },
               { "role": "user", "content": query }
           ]
       });
       const curlcmd = `curl -s https://api.openai.com/v1/chat/completions
          -H "Content-Type: application/json"
          -H "Authorization: Bearer ${openaiKey}"
          -d '${payload}' #`.replace(/\n/g, "");
        if (decaiDebug) {
            console.log(curlcmd);
        }
        const res = r2.syscmds(curlcmd);
        try {
            return JSON.parse(res).choices[0].message.content;
        } catch(e) {
            console.error(e);
            console.log(res);
        }
        return "error invalid response";
    }
    function r2aiOpenAPI(msg, hideprompt) {
	const query = hideprompt? msg: decprompt + ", Transform this pseudocode into " + decaiLanguage + "\n" + msg;
        const payload = JSON.stringify({ "prompt": query });
        const curlcmd = `curl -s ${decaiHost}:${decaiPort}/completion
          -H "Content-Type: application/json"
          -d '${payload}' #`.replace(/\n/g, "");
        if (decaiDebug) {
            console.log(curlcmd);
        }
        const res = r2.syscmds(curlcmd);
        try {
            return JSON.parse(res).content;
        } catch(e) {
            console.error(e);
            console.log(res);
        }
        return "error invalid response";
    }
    function decaiDecompile(args, extraQuery, useCache) {
        if (useCache) {
           const cachedAnotation = r2.cmd("anos").trim();
           if (cachedAnotation.length > 0) {
               return cachedAnotation;
	   }
        }
        let out = "";
        const appendQuery = extraQuery? " " + args: "";
        const origColor = r2.cmd("e scr.color");
        try {
            args = args.slice(2).trim();
            const file = "/tmp/.pdc.txt";
            r2.call("rm .pdc.txt");
            r2.call("rm " + file);
            r2.cmd("echo > " + file);
            let count = 0;
            let text = "";
            if (decaiContextFile !== "") {
                if (r2.cmd2("test -f " + decaiContextFile).value === 0) {
                    text += "Context:\n";
                    text += "[RULES]\n";
                    text += r2.cmd("cat " + decaiContextFile);
                    text += "[/RULES]\n";
                }
            }
            r2.cmd("e scr.color=0");
            for (const c of decaiCommands.split(",")) {
                if (c.trim() === "") {
                    continue;
                }
                const oneliner = (extraQuery || args.trim().length === 0)? c : c + "@@= " + args;
                const output = r2.cmd(oneliner);
                if (output.length > 5) {
                    text += "Output from " + c + ":\n";
                    text += "[BEGIN]\n";
                    text += output + "\n";
                    text += "[END]\n";
                    count++;
                }
            }
            r2.cmd("e scr.color=" + origColor);
            if (count === 0) {
                console.error("Nothing to do.");
                return;
            }
            r2ai("-R");
            const query = (decprompt + appendQuery).trim() + ". Transform this pseudocode into " + decaiLanguage;
            out = r2ai(query, text);
            lastOutput = out;
        } catch (e) {
            r2.cmd("e scr.color=" + origColor);
            console.error(e, e.stack);
        }
        if (useCache && out.length > 1) {
           r2.call("ano=base64:" + b64(out));
        }
	return out;
    }
    function fileDump(fileName, fileData) {
        const d = b64(fileData);
        r2.cmd("p6ds " + d + " > " + fileName);
    }
    function r2ai(queryText, fileData, hideprompt) {
        if (!fileData) {
            fileData = "";
        }
        fileData = fileData.replace(/\`/g, '').replace(/'/g, '"');
        queryText = queryText.replace(/'/g, '');
        if (decaiApi === "r2" || decaiApi === "r2ai") {
            const fileName = "/tmp/.pdc.txt";
            fileDump(fileName, fileData);
            const q = queryText.startsWith("-")? queryText: ["-i", fileName, queryText].join(" ");
            const host = decaiHost + ":" + decaiPort + "/cmd"; // "http://localhost:8080/cmd";
            const ss = q.replace(/ /g, "%20").replace(/'/g, "\\'");
            const cmd = 'curl -s "' + host + '/' + ss + '" || echo "Cannot curl, use r2ai-server or r2ai -w"';
            if (decaiDebug) {
                console.error(cmd);
            }
            return r2.syscmds(cmd);
            // return r2.cmd(cmd);
        }
        if (fileData === "" || queryText.startsWith("-")) { // -i
            return "";
        }
        const q = queryText + ":\n" + fileData;
        if (decaiApi === "anthropic" || decaiApi === "claude") {
            return r2aiAnthropic(q, hideprompt);
        }
        if (decaiApi === "huggingface" || decaiApi === "hf") {
            return r2aiHuggingFace(q, hideprompt);
        }
        if (decaiApi === "openapi") {
            return r2aiOpenAPI(q, hideprompt);
        }
        if (decaiApi === "openai") {
            return r2aiOpenAI(q, hideprompt);
        }
        return "Unknown value for 'decai -e api'. Use r2ai, claude, hf, openapi or openai";
    }
    function r2aidec(args) {
        if (args === "") {
            usage();
        } else if (args[0] === "-") {
            let out = "";
            switch (args[1]) {
            case "H": // "-H"
                console.log(decaiHelp);
                break;
            case "n": // "-n"
            case "f": // "-f"
                out = r2.cmd("pdc");
                var considerations = r2.cmd("fd.").trim().split(/\n/).filter(x=>!x.startsWith("secti")).join(",");
                // console.log(considerations);
                r2ai("-R");
                out = r2ai("give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: " + considerations, out).trim();
		out += " @ " + r2.cmd("?v $FB").trim();
                break;
            case "v": // "-v"
                out = r2.cmd("afv;pdc");
                r2ai("-R");
                out = r2ai("guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands", out);
                break;
            case "i": // "-i"
                args = args.slice(2).trim().split(/ /g, 2);
                if (args.length === 2) {
                    const file = args[0];
                    const query = args[1];
                    const fileData = r2.cmd("cat " + file);
                    console.log(r2ai(query, fileData, true));
                } else {
                    console.log("Use: decai -i [file] [query ...]");
                }
                break;
            case "r": // "-r"
                args = args.slice(2).trim();
                if (args) {
                    decprompt = args
                } else {
                    console.log(decprompt);
                }
                break;
            case "V": // "-V"
                r2aidec("-d find vulnerabilities, dont show the code, only show the response");
                break;
            case "e": // "-e"
                args = args.slice(2).trim();
                if (args) {
                    decaiEval(args);
                } else {
                    console.log("decai -e api=" + decaiApi);
                    console.log("decai -e host=" + decaiHost);
                    console.log("decai -e port=" + decaiPort);
                    console.log("decai -e prompt=" + decprompt);
                    console.log("decai -e ctxfile=" + decaiContextFile);
                    console.log("decai -e cmds=" + decaiCommands);
                    console.log("decai -e cache=" + decaiCache);
                    console.log("decai -e lang=" + decaiLanguage);
                    console.log("decai -e hlang=" + decaiHumanLanguage);
                    console.log("decai -e debug=" + decaiDebug);
                    console.log("decai -e model=" + decaiModel);
                }
                break;
            case "q": // "-q"
                out = r2ai(args.slice(2).trim());
                break;
            case "Q": // "-Q"
                out = r2ai(args.slice(2).trim(), lastOutput);
                break;
            case "x": // "-x"
                var origColor = r2.cmd("e scr.color");
                r2.cmd("e scr.color=0");
                var cmds = decaiCommands; // +",axt";
                out = "[BEGIN]" + cmds.split(",").map(r2.cmd).join("\n") + "[END]";
                r2.cmd("e scr.color=" + origColor);
                r2ai("-R");
                out = r2ai("Analyze function calls, comments and strings, ignore registers and memory accesess. Considering the references and involved loops make explain the purpose of this function in one or two short sentences. Output must be only the translation of the explanation in " + decaiHumanLanguage, out, true);
                break;
            case "d": // "-d"
                out = decaiDecompile(args, false, decaiCache);
                break;
            case "dd": // "-dd"
                out = decaiDecompile(args, false, false);
                break;
            case "D": // "-D"
                out = decaiDecompile(args, true, false);
                break;
            default:
                usage();
                break;
            }
	    if (out) {
                r2.log(out);
	    }
        } else {
            usage();
        }
        return true;
    }
    r2.unload("core", command);
    r2.plugin("core", function () {
        function coreCall(cmd) {
            if (cmd.startsWith(command)) {
                var args = cmd.slice(command.length).trim();
                return r2aidec(args);
            }
            return false;
        }
        return {
            "name": command,
            "license": "MIT",
            "desc": "r2 decompiler based on r2ai",
            "call": coreCall,
        };
    });
})();
