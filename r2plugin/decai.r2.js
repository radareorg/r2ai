(function () {
    const decaiHelp = `
You need r2ai webserver to be running, to do this run 'r2ai -w' in a separate terminal.

  $ r2pm -ci r2ai

The best model for decompiling is ClaudeAI from Anthropic:

  $ r2pm -r r2ai
  $ echo $CLAUDEAPIKEY > ~/.r2ai.anthropic
  [r2ai:0x0000000]> -m anthropic:claude-3-5-sonnet-20240620
  [r2ai:0x0000000]> -w
  Webserver listening at port 8080

If you want to run r2ai in local you should use llama3, gemma or mistral

  [r2ai:0x0000000]> -m TheBloke/Mistral-7B-Instruct-v0.2-GGUF
  [r2ai:0x0000000]> -w

You can also make r2ai -w talk to an 'r2ai-server' using this line:

  [r2ai:0x0000000]> -m openapi:http://localhost:8080
  [r2ai:0x0000000]> -e http.port=8082

  [0x0000000]> decai -e host=http://localhost:8082
`;
    const command = "decai";
    let decaiHost = "http://localhost";
    let decaiPort = "8080";
    let decaiApi = "r2"; // uses /cmd endpoint
    let decaiCommands = "pdc";
    let decaiLanguage = "C";
    let decaiDebug = false;
    let decprompt = "optimize this pseudodisasm into high level quality decompiled code,";
    decprompt += "replace goto with proper control flow statements,";
    decprompt += "use better names for variables,";
    decprompt += "show only the code snippet,";
    decprompt += "do not introduce or explain the code,";
    decprompt += "combine the compare line with the conditional line below,";
    decprompt += "use better names for variables. combine the compare line with the conditional line below,";
    decprompt += "keep comments from source";
    decprompt += "remove unnecessary assignments inlining them into the function argument calls, add a comment on top explaining whats the function for in one sentence";
    // simplest the better
    // decprompt = "do not explain, just improve and merge the following decompiled functions, remove gotos and use better names for variables. optimize for readability, assume calling conventions to fill function arguments";
    ///// using commands and dots makes some models perform very large outputs or fall in infinite loops
//    decprompt = "do not introduce, comment or explain. reply only with the optimized code, improve and merge the following decompiled functions, remove gotos and use better names for variables, focus on readability";
    decprompt = "remove gotos use better variable names and merge cleanup the given decompiled code for readability purposes. do not explain the code.";

    function decaiEval(arg) {
        const [k, v] = arg.split("=");
        if (!v) {
            switch (k) {
            case "debug":
                console.log(decaiDebug);
                break;
            case "api":
                console.log(decaiApi);
                break;
            case "lang":
                console.log(decaiLanguage);
                break;
            case "cmds":
                console.log(decaiCommands);
                break;
            case "prompt":
                console.log(decprompt);
                break;
            case "host":
                console.log(decaiHost);
                break;
            case "port":
                console.log(decaiPort);
                break;
            }
            return;
        }
        switch (k) {
        case "debug":
            decaiDebug = (v === "true" || v === "1");
            break;
        case "api":
            decaiApi = v;
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
        }
    }
    function usage() {
        console.error("Usage: " + command + " (-h) ...");
        console.error(" " + command + " -d  - decompile");
        console.error(" " + command + " -e  - eval vars");
        console.error(" " + command + " -r  - role");
        console.error(" " + command + " -m  - model");
        console.error(" " + command + " -h  - show help");
        console.error(" " + command + " -H  - help setting up r2ai");
        console.error(" " + command + " -M  - list most relevant models");
        console.error(" " + command + " -x  - eXplain");
        console.error(" " + command + " -n  - suggest better function name");
        console.error(" " + command + " -v  - show local variables");
        console.error(" " + command + " -V  - find vulnerabilities");
    }
    function r2ai(s) {
        if (decaiApi === "r2") {
            const host = decaiHost + ":" + decaiPort + "/cmd"; // "http://localhost:8080/cmd";
            const ss = s.replace(/ /g, "%20").replace(/'/g, "\\'");
            const cmd = '\'!curl -s "' + host + '/' + ss + '" > .pdc.txt || echo Cannot curl, use r2ai-server or r2ai -w #';
            if (decaiDebug) {
                console.error(cmd);
            }
            r2.cmd0(cmd);
            return r2.cmd('cat .pdc.txt');
        }
        if (!s.startsWith ("-i")) {
            return;
        }
        const msg = r2.cmd("cat /tmp/.pdc.txt");
/*
        const payload2 = JSON.stringify({
        // "model": decaiModel,
            "messages": [
                {"role": "system", "content": decprompt }, // "You are a helpful assistant."},
                {"role": "user", "content": msg } //  "Can you explain how to use the OpenAI API with curl?"}
            ],
        });
        const curlcmd2 = `'!curl -s -o .decai.txt ${decaiHost}:${decaiPort}/v1/chat/completions
          -H "Content-Type: application/json"
          -d '${payload2}' #`.replace(/\n/g, "");
                const payload = JSON.stringify({ "prompt": decprompt + "\n" + msg });
          // -H "Authorization: Bearer YOUR_API_KEY"
        // return JSON.parse(res).choices[0].message.content;
*/
        const curlcmd = `'!curl -s -o .decai.txt ${decaiHost}:${decaiPort}/completion
          -H "Content-Type: application/json"
          -d '${payload}' #`.replace(/\n/g, "");
        console.log(curlcmd);
        r2.cmd0(curlcmd);
        const res = r2.cmd("cat .decai.txt");
        try {
            return JSON.parse(res).content;
        } catch(e) {
            console.error(e);
            console.log(res);
        }
        return "error invalid response";
    }
    function r2aidec(args) {
        if (args === "") {
            usage();
        } else if (args[0] === "-") {
            var out = "";
            switch (args[1]) {
            case "H": // "-H"
                console.log(decaiHelp);
                break;
            case "n": // "-n"
            case "f": // "-f"
                r2.cmd("pdc > /tmp/.pdc.txt");
                var considerations = r2.cmd("fd.").trim().split(/\n/).filter(x=>!x.startsWith("secti")).join(",");
                // console.log(considerations);
                r2ai("-R");
                out = r2ai("-i /tmp/.pdc.txt give me a better name for this function. the output must be: 'afn NEWNAME'. consider: " + considerations);
                break;
            case "v": // "-v"
                r2.cmd("pdc > /tmp/.pdc.txt");
                r2ai("-R");
                out = r2ai("-i /tmp/.pdc.txt show only the local variables.");
                break;
            case "r": // "-r"
                args = args.slice(2).trim();
                if (args) {
                    decprompt = args
                } else {
                    console.log(decprompt);
                }
                break;
            case "M": // "-M"
                console.log("decai -m openai:gpt-4o");
                console.log("decai -m anthropic:claude-3-5-sonnet-20240620");
                console.log("decai -m FaradayDotDev/llama-3-8b-Instruct-GGUF");
                console.log("decai -m bartowski/gemma-2-9b-it-GGUF");
                console.log("decai -m cognitivecomputations/dolphin-2.9.3-mistral-nemo-12b-gguf");
                console.log("decai -m second-state/Mistral-Nemo-Instruct-2407-GGUF");
                console.log("decai -m Undi95/Utopia-13B-GGUF");
                break;
            case "m": // "-m"
                args = args.slice(2).trim();
                if (args) {
                    console.log(r2ai("-m " + args));
                } else {
                    console.log(r2ai("-m"));
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
                    console.log("decai -e host=" + decaiHost);
                    console.log("decai -e port=" + decaiPort);
                    console.log("decai -e prompt=" + decprompt);
                    console.log("decai -e cmds=" + decaiCommands);
                    console.log("decai -e lang=" + decaiLanguage);
                    console.log("decai -e debug=" + decaiDebug);
                    console.log("decai -e api=" + decaiApi);
                }
                break;
            case "x": // "-x"
                r2.cmd("pdsf > /tmp/.pdc.txt");
                r2ai("-R");
                out = r2ai("-i /tmp/.pdc.txt Explain what's this function doing in one sentence.")
                break;
            case "D": // "-D"
                try {
                    args = args.slice(2).trim();
                    r2.cmd("'!echo 'Consider:\\n <code>' > /tmp/.pdc.txt");
                    r2.cmd("pdc >> /tmp/.pdc.txt");
                    // r2.cmd("'!cat /tmp/.pdc.txt0 >> /tmp/.pdc.txt");
                    r2.cmd("'!echo '</code>\\n and :\\n<code>' >> /tmp/.pdc.txt");
                    r2.cmd("pdg >> /tmp/.pdc.txt");
                    r2.cmd("'!echo '</code>\\n and :\\n<code>' >> /tmp/.pdc.txt");
                    r2.cmd("pdd >> /tmp/.pdc.txt");
                    r2.cmd("'!echo '</code>' >> /tmp/.pdc.txt");
                    r2ai("-R");
                    const p = decprompt + ". replace variables with the actual strings. Output in "+ decaiLanguage;
                    out = r2ai("-i /tmp/.pdc.txt " + (p + " " + args).trim());
                } catch (e) {
                    console.error(e);
                }
                break;
            case "d": // "-d"
                try {
                    args = args.slice(2).trim();
                    r2.call("rm .pdc.txt");
                    const file = "/tmp/.pdc.txt";
                    r2.call("rm " + file);
                    r2.cmd("echo > "+file);
                    let count = 0;
                    for (const c of decaiCommands.split(",")) {
                        if (c.trim() === "") {
                            continue;
                        }
                        // console.error("Running " + c);
                        r2.cmd("echo Output from " + c + ": >> /tmp/.pdc.txt");
                        // r2.cmd("echo BEGIN >> /tmp/.pdc.txt");
                        r2.cmd(c + " > $tmp");
                        if (r2.cmd("cat $tmp").length > 5) {
                            r2.cmd("echo [BEGIN] >> "+file);
                            r2.cmd("cat $tmp >> " + file);
                            r2.cmd("echo [END] >> " + file);
                            count++;
                        }
                    }
                    if (count === 0) {
                        console.error("Nothing to do.");
                        break;
                    }
                    r2ai("-R");
                    var query = (decprompt + " " + args).trim() + ". Output in " + decaiLanguage;
                    out = r2ai("-i /tmp/.pdc.txt " + query);
                } catch (e) {
                    console.error(e);
                }
                break;
            default:
                usage();
                break;
            }
            r2.log(out);
        } else {
            console.log("ARGS: " + args);
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
