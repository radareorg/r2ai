(function () {
  // Constants and configuration
  const COMMAND = "decai";
  const DEFAULT_PROMPT = "Transform this pseudocode and respond ONLY with plain code (NO explanations, comments or markdown), Change 'goto' into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and strings from comments like 'string:', Reduce lines of code and fit everything in a single function, Remove all dead code";
  
  const HELP_TEXT = {
	// AITODO: use multiline string here
    decai: `# Using Decai\n\nDecai is the radare2 plugin for decompiling functions with the help of language models.\nBy default uses a local ollama server, but can you can pick any other service by using 'decai -e api=?'.\n\n[0x00000000]> decai -e api=?\nr2ai claude deepseek gemini hf mistral ollama openapi openai vllm xai\n\n## Using Ollama\n\n* Visit https://ollama.com to install it.\n* Download the model of choice: 'ollama run llama3.3'\n* Configure decai to use the given model with: 'decai -e model=?'\n\nThese are the most recommended models for decompiling in local:\n\n* hhao/qwen2.5-coder-tools:latest (18GB of ram)\n* hhao/qwen2.5-coder-tools:32b (24GB of ram required)\n\n## Common Options\n* 'decai -e baseurl=<url>' override default host and port for API endpoint (e.g., 'http://localhost:11434')\n\n* 'decai -e deterministic=true' to remove randomness from decompilation responses\n* 'decai -e lang=Python' to output the decompilation in Python instead of C\n* 'decai -e hlang=Catalan' to add comments or explanations in that language (instead of English)\n* 'decai -e cmds=pdd,pdg' use r2dec and r2ghidra instead of r2's pdc as input for decompiling\n* 'decai -e prompt=..' default prompt must be fine for most models and binaries, feel free to tweak it\n\n## API Keys\n\nRemove services like OpenAI, Mistral, Anthropic, Grok, Gemini, .. require API keys to work.\n\nSee 'decai -k' to list the status of available APIkeys\n\nDecai will pick them from the environment or the config files in your home:\n\n* echo KEY > ~/.r2ai.openai-key\n* export OPENAI_API_KEY=...\n\n## Using the R2AI Server:\n\nInstall r2ai or r2ai-server with r2pm:\n\n[0x0000000]> decai -e api=r2ai\n[0x0000000]> r2pm -ci r2ai\n\nChoose one of the recommended models (after r2pm -r r2ai):\n\n* -m ibm-granite/granite-20b-code-instruct-8k-GGUF\n* -m QuantFactory/granite-8b-code-instruct-4k-GGUF\n* -m TheBloke/Mistral-7B-Instruct-v0.2-GGUF\n\nStart the webserver:\n\n$ r2pm -r r2ai-server -l r2ai -m granite-8b-code-instruct-4k.Q2_K\n\n## Permanent Settings\n\nYou can write your custom decai commands in your ~/.radare2rc file.\n\n`,
    auto: `# Radare2 Auto Mode\n\nUse function calling to execute radare2 commands in order to resolve the user request defined in the "User Prompt" section, analyze the responses attached in the "Command Results" section.\n\n## Function Calling\n\nRespond ONLY using plain JSON. Process user query and decide which function calls are necessary to solve the task.\n\n1. Analyze the user request to determine if we need to run commands to extend the knowledge and context of the problem.\n2. If function call is needed, construct the JSON like this:\n - Fill the "action" key with the "r2cmd" value.\n - Specify the "command" as a string.\n - Optionally, provide a "reason" and "description"\n3. If the answer can be provided and no more function calls are required:\n - Use the key "action": "reply".\n - Include "response" with the direct answer to the user query.\n\nReturn the result as a JSON object.\n\n### Sample Function Calling Communication\n\nCommand Results: already performed actions with their responses\nUser Prompt: "Count how many functions we have here."\nResponse:\n{\n    "action": "r2cmd",\n    "command": "aflc",\n    "description": "Count functions"\n    "reason": "Evaluate if the program is analyzed before running aaa"\n}\n\n## Rules\n\nUse radare2 to resolve user requests.\n\n* Explain each step in the "reason" field of the JSON.\n* Follow the initial analysis instructions.\n* Output only valid JSON as specified.\n* Decompile and inspect functions, starting from main.\n* Run only the needed commands to gather info.\n* Use "@ (address|symbol)" to seek temporarily.\n* Output should be a verbose markdown report.\n* Use "sym." or "fcn." prefixes if "pdc" is empty.\n* If a seek fails, use "f~name" to find the symbol's address.\n\n### Initial Analysis\n\n1. Run "aflc" to count the number of functions\n2. If the output of "aflc" is "0" run "aaa" once, then "aflc" again\n3. Run only one command at a time (do not use ";")\n\n### Special cases\n\n* On Swift binaries run "/az" to find assembly constructed strings\n* For better function decompilation results use "pdd"\n\n### Planing Steps\n\n1. Rephrase the user request into clear tasks.\n2. Review available commands and choose only what's needed.\n3. Follow the task list step-by-step.\n4. Avoid redundant or repeated actions.\n5. Minimize token use by acting efficiently.\n6. Solve the problem quickly and accurately.\n\n## Functions or Commands\n\n* "i" : get information from the binary\n* "is" : list symbols\n* "izqq" : show all strings inside the binary\n* "aflm" : list all functions and their calls\n* "aflc" : count the amount of functions analyzed\n* "ies" : show entrypoints symbols\n* "pdsf" : show strings and function names referenced in function\n* "iic" : classify imported symbols (network, format string, thread unsafe, etc)\n* "pdc" : decompile function\n* "iiq" : enumerate the imported symbols\n* "izqq~http:,https:" : filter strings for http and https network urls\n* "ilq" : Enumerate libraries and frameworks\n\n`
  };

  // Configuration state
  const state = {
    decopipe: { use: false },
    host: "http://localhost",
    port: "11434",
    baseurl: "",
    api: "ollama",
    pipeline: "",
    commands: "pdc",
    yolo: false,
    tts: false,
    language: "C",
    humanLanguage: "English",
    deterministic: true,
    debug: false,
    think: -1,
    useFiles: false,
    contextFile: "",
    model: "",
    cache: false,
    maxInputTokens: -1,
    prompt: DEFAULT_PROMPT,
    lastOutput: ""
  };

  // Utility functions
  const utils = {
    tmpdir: (path) => {
      const dir = r2.cmd("-e dir.tmp").trim() ?? ".";
      return dir + "/" + path;
    },

    fileExists: (path) => {
      if (r2.cmd2("test -h").logs[0].message.indexOf("-fdx") !== -1) {
        return true; // r2 is old
      }
      return r2.cmd("'test -vf " + path).startsWith("found");
    },

    padRight: (str, length) => str + " ".repeat(Math.max(0, length - str.length)),

    trimAnsi: (str) => str.replace(/\x1b\[[0-9;]*m/g, ""),

    trimDown: (out) => {
      const jsonMatch = out.match(/```json\s*([\s\S]*?)```/);
      return jsonMatch && jsonMatch[1] ? jsonMatch[1].trim() : out;
    },

    trimJson: (out) => {
      const bob = out.indexOf("{");
      if (bob !== -1) out = out.slice(bob);
      const eob = out.indexOf("}");
      if (eob !== -1) out = out.slice(0, eob + 1);
      return out;
    },

    b64: (str) => btoa(str), // Assuming base64 encoding function exists

    fileDump: (fileName, fileData) => {
      const d = utils.b64(fileData);
      r2.cmd("p6ds " + d + " > " + fileName);
    },

    filterResponse: (msg) => {
      if (state.think !== 2) {
        msg = msg.replace(/<think>[\s\S]*?<\/think>/gi, "");
      }
      return msg.split("\n")
        .filter(line => !line.trim().startsWith("```"))
        .join("\n");
    },

    debug: {
      log: (msg) => state.debug && console.log(msg)
    }
  };

  // API key management
  const apiKeys = {
    get: (provider, envvar) => {
      const keyEnv = r2.cmd("'%" + envvar).trim();
      if (keyEnv.indexOf("=") === -1 && keyEnv !== "") {
        return [keyEnv.trim(), null, "env"];
      }
      
      const keyPath = "~/.r2ai." + provider + "-key";
      if (utils.fileExists(keyPath)) {
        const keyFile = r2.cmd("'cat " + keyPath);
        return keyFile === "" 
          ? [null, "Cannot read " + keyPath, "no"]
          : [keyFile.trim(), null, "file"];
      }
      return [null, "Not available", "nope"];
    },

    list: () => {
      const providers = {
        "mistral": "MISTRAL_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY", 
        "huggingface": "HUGGINGFACE_API_KEY",
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "xai": "XAI_API_KEY",
        "ollama": "OLLAMA_API_KEY",
        "ollamacloud": "OLLAMA_API_KEY"
      };
      
      Object.entries(providers).forEach(([key, env]) => {
        const status = apiKeys.get(key, env)[2];
        console.log(status, "\t", key);
      });
    }
  };

  // HTTP utilities
  const http = {
    get: (url, headers) => {
      const heads = headers.map(x => `-H "${x}"`).join(" ");
      const cmd = `curl -s ${url} ${heads} -H "Content-Type: application/json"`;
      return JSON.parse(r2.syscmds(cmd));
    },

    post: (url, headers, payload) => {
      const heads = headers.map(x => `-H "${x}"`).join(" ");
      
      const curlArgs = (url, heads, payload) => {
        const escapedPayload = payload.replace(/'/g, "'\\''");
        const cmd = `curl -s '${url}' ${heads} -d '${escapedPayload}' -H "Content-Type: application/json"`;
        utils.debug.log(cmd);
        return r2.syscmds(cmd);
      };

      const curlFile = (url, heads, payload) => {
        const tmpfile = r2.fdump(payload);
        const cmd = `curl -s '${url}' ${heads} -d '@${tmpfile}' -H "Content-Type: application/json"`;
        utils.debug.log(cmd);
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
        console.error("output:", output);
        console.error(e, e.stack);
        return { error: e.stack };
      }
    }
  };

  // Configuration management
  const config = {
    handlers: {
      pipeline: {
        get: () => state.pipeline,
        set: (v) => {
          state.pipeline = v;
          try {
            state.decopipe = JSON.parse(r2.cmd("cat " + v));
          } catch (e) {
            console.error(e);
          }
        }
      },
      model: {
        get: () => state.model,
        set: (v) => {
          if (v === "?") {
            models.listFor(state.api);
          } else {
            state.model = v.trim();
          }
        }
      },
      deterministic: {
        get: () => state.deterministic,
        set: (v) => state.deterministic = v === "true" || v === "1"
      },
      files: {
        get: () => state.useFiles,
        set: (v) => state.useFiles = v === "true"
      },
      think: {
        get: () => state.think,
        set: (v) => state.think = (v === "true") ? 1 : (v === "false") ? 0 : +v
      },
      debug: {
        get: () => state.debug,
        set: (v) => state.debug = v === "true" || v === "1"
      },
      api: {
        get: () => state.api,
        set: (v) => {
          if (v === "?") {
            const providersList = Object.keys(providers).filter((x)=> {
              return x === x.toLowerCase();
            }).join("\n");
            console.error(providersList);
          } else {
            state.api = v;
          }
        }
      },
      lang: {
        get: () => state.language,
        set: (v) => state.language = v
      },
      hlang: {
        get: () => state.humanLanguage,
        set: (v) => state.humanLanguage = v
      },
      cache: {
        get: () => state.cache,
        set: (v) => state.cache = v === "true" || v == 1
      },
      cmds: {
        get: () => state.commands,
        set: (v) => state.commands = v
      },
      tts: {
        get: () => state.tts,
        set: (v) => state.tts = v === "true" || v == 1
      },
      yolo: {
        get: () => state.yolo,
        set: (v) => state.yolo = v === "true" || v == 1
      },
      prompt: {
        get: () => state.prompt,
        set: (v) => state.prompt = v
      },
      ctxfile: {
        get: () => state.contextFile,
        set: (v) => state.contextFile = v
      },
      baseurl: {
        get: () => state.baseurl,
        set: (v) => state.baseurl = v
      },
      maxtokens: {
        get: () => state.maxInputTokens,
        set: (v) => state.maxInputTokens = v
      }
    },

    eval: (arg) => {
      const [k, v] = arg.split("=");
      if (!config.handlers[k]) {
        console.error("Unknown config key");
        return;
      }
      
      if (typeof v !== "undefined") {
        config.handlers[k].set(v);
      } else {
        console.log(config.handlers[k].get());
      }
    },

    listAll: () => {
      Object.keys(config.handlers).forEach(key => {
        const value = config.handlers[key].get();
        console.log("decai -e " + key + "=" + value);
      });
    }
  };

  // Model management
  const models = {
    listClaude: () => {
      const key = apiKeys.get("anthropic", "ANTHROPIC_API_KEY");
      if (key[1]) throw new Error(key[1]);
      
      const headers = ["x-api-key: " + key[0], "anthropic-version: 2023-06-01"];
      const response = http.get("https://api.anthropic.com/v1/models", headers);
      return response.data.map(model => model.id).join("\n");
    },

    listMistral: () => {
      const key = apiKeys.get("mistral", "MISTRAL_API_KEY");
      if (key[1]) throw new Error(key[1]);
      
      const headers = ["Authorization: Bearer " + key[0]];
      const response = http.get("https://api.mistral.ai/v1/models", headers);
      const uniqByName = arr => arr.filter((obj, i, self) => 
        self.findIndex(o => o.name === obj.name) === i);
      
      return uniqByName(response.data).map(model =>
        [
          utils.padRight(model.name, 30),
          utils.padRight("" + model.max_context_length, 10),
          model.description
        ].join(" ")
      ).join("\n");
    },

     listOpenai: () => {
        const key = apiKeys.get("openai", "OPENAI_API_KEY");
        if (key[1]) throw new Error(key[1]);

        const headers = ["Authorization: Bearer " + key[0]];
        const response = http.get("https://api.openai.com/v1/models", headers);
        return response.data.map(model => model.id).join("\n");
      },
     listOllama: () => {
       const base = state.baseurl || (state.host + ":" + state.port);
       const cmd = `curl -s ${base}/api/tags`;
       const res = r2.syscmds(cmd);

       try {
         const models = JSON.parse(res).models;
         return models.map(model => model.name).join("\n");
       } catch (e) {
         console.error(e);
         console.log(res);
         return "error invalid response";
       }
     },

     listOllamaCloud: () => {
       const key = apiKeys.get("ollama", "OLLAMA_API_KEY");
       if (key[1]) throw new Error(key[1]);

       const headers = ["Authorization: Bearer " + key[0]];
       const response = http.get("https://ollama.com/v1/models", headers);
       return response.data.map(model => model.id).join("\n");
     },

    listFor: (api) => {
      const modelLists = {
        ollama: () => console.log(models.listOllama()),
        openapi: () => console.log(models.listOllama()),
        openai: () => console.log(models.listOpenai()),
        groq: () => console.log("meta-llama/llama-4-scout-17b-16e-instruct"),
        gemini: () => {
          const geminiModels = [
            "gemini-2.0-flash", "gemini-2.0-flash-lite",
            "gemini-1.5-pro", "gemini-1.5-flash"
          ];
          geminiModels.forEach(model => console.log(model));
        },
        claude: () => {
          try {
            console.log(models.listClaude());
          } catch (e) {
            console.error(e);
          }
          const claudeModels = [
            "claude-3-5-sonnet-20241022", "claude-3-7-sonnet-20250219",
            "claude-opus-4-20250514", "claude-sonnet-4-20250514"
          ];
          claudeModels.forEach(model => console.log(model));
        },
        anthropic: () => models.listFor("claude"),
        xai: () => {
          const xaiModels = ["grok-2", "grok-beta"];
          xaiModels.forEach(model => console.log(model));
        },
        mistral: () => {
          try {
            console.log(models.listMistral());
          } catch (e) {
            console.error(e, e.stack);
          }
          console.log("codestral-latest");
        },
         ollamacloud: () => {
           try {
             console.log(models.listOllamaCloud());
           } catch (e) {
             console.error(e);
           }
         }
      };

      const listFunction = modelLists[api];
      if (listFunction) {
        listFunction();
      }
    }
  };

  // AI providers - simplified structure
  const providers = {
    buildQuery: (msg, hideprompt) => {
      if (state.think >= 0) {
        if (state.think === 0) {
          msg += ' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".';
          msg += " /no_think";
        } else if (state.think > 0) {
          msg = "Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer." + msg;
        }
      }
      return hideprompt ? msg : state.prompt + providers.languagePrompt() + msg;
    },

    languagePrompt: () => "\n.Translate the code into " + state.language + " programming language\n",

    anthropic: (msg, hideprompt) => {
      const key = apiKeys.get("anthropic", "ANTHROPIC_API_KEY");
      if (key[1]) return "Cannot read ~/.r2ai.anthropic-key";

      const model = state.model || "claude-3-7-sonnet-20250219";
      const query = providers.buildQuery(msg, hideprompt);
      
      const payload = {
        model: model,
        max_tokens: 5128,
        messages: [{ role: "user", content: query }]
      };

      if (state.deterministic) {
        Object.assign(payload, { temperature: 0, top_p: 0, top_k: 1 });
      }

      const headers = [
        "anthropic-version: 2023-06-01",
        "x-api-key: " + key[0]
      ];

      try {
        const res = http.post("https://api.anthropic.com/v1/messages", headers, JSON.stringify(payload));
        return utils.filterResponse(res.content[0].text);
      } catch (e) {
        return "ERROR: " + (res.error?.message || e.message);
      }
    },

    openai: (msg, hideprompt) => {
      const model = state.model || "gpt-5-mini";
      const query = providers.buildQuery(msg, hideprompt);

      const payload = {
        stream: false,
        model: model,
        messages: [{ role: "user", content: query }]
      };

      if (state.deterministic) {
        // payload.options = { };
      }

      if (state.baseurl === "") {
        state.baseurl = "https://api.openai.com/";
      }
      const base = state.baseurl || (state.host + ":" + state.port);
      const url = base + "/v1/chat/completions";
      const key = apiKeys.get("openai", "OPENAI_API_KEY");
      if (key[1]) return "Cannot read ~/.r2ai.openai-key";
      const headers = [
        "Authorization: Bearer " + key[0]
      ];

      try {
        const res = http.post(url, headers, JSON.stringify(payload));
        return utils.filterResponse(res.choices[0].message.content);
      } catch (e) {
        return "ERROR: " + e.message;
      }
    },
    ollama: (msg, hideprompt) => {
      const model = state.model || "qwen2.5-coder:latest";
      const query = providers.buildQuery(msg, hideprompt);

      const payload = {
        stream: false,
        model: model,
        messages: [{ role: "user", content: query }]
      };

      if (state.deterministic) {
        payload.options = {
          repeat_last_n: 0,
          top_p: 0.0,
          top_k: 1.0,
          temperature: 0.0,
          repeat_penalty: 1.0,
          seed: 123
        };
      }

      const base = state.baseurl || (state.host + ":" + state.port);
      const url = base + "/api/chat";

      try {
        const res = http.post(url, [], JSON.stringify(payload));
        return utils.filterResponse(res.message.content);
      } catch (e) {
        if (res.error?.indexOf("try pulling")) {
          const modelName = res.error.split(/"/g)[1];
          res.error += "\n!ollama run " + modelName;
        }
        return "ERROR: " + (res.error || e.message);
      }
    },

    ollamacloud: (msg, hideprompt) => {
      const key = apiKeys.get("ollama", "OLLAMA_API_KEY");
      if (key[1]) return "Cannot read ~/.r2ai.ollama-key";

      const model = state.model || "gpt-oss:120b";
      const query = providers.buildQuery(msg, hideprompt);

      const payload = {
        model: model,
        messages: [{ role: "user", content: query }]
      };

      if (state.deterministic) {
        payload.temperature = 0;
        payload.top_p = 0;
      }

      const headers = [
        "Authorization: Bearer " + key[0]
      ];

      // NOTE: ollama cloud is actually openai. so we are dupping logic here
      try {
        const res = http.post("https://ollama.com/v1/chat/completions", headers, JSON.stringify(payload));
        return utils.filterResponse(res.choices[0].message.content);
      } catch (e) {
        return "ERROR: " + (res.error?.message || e.message);
      }
    }

    // Additional providers would follow similar pattern...
  };

  // Main AI function dispatcher
  function r2ai(queryText, fileData, hideprompt) {
    if (!fileData) fileData = "";
    
    fileData = fileData.replace(/`/g, "");
    queryText = queryText.replace(/'/g, "");

    if (state.api === "r2" || state.api === "r2ai") {
      const fileName = utils.tmpdir(".pdc.txt");
      utils.fileDump(fileName, fileData);
      const q = queryText.startsWith("-") ? queryText : ["-i", fileName, queryText].join(" ");
      const host = state.baseurl ? state.baseurl + "/cmd" : state.host + ":" + state.port + "/cmd";
      const ss = q.replace(/ /g, "%20").replace(/'/g, "\\'");
      const cmd = 'curl -s "' + host + "/" + ss + '" || echo "Cannot curl, use r2ai-server or r2ai -w"';
      utils.debug.log(cmd);
      return r2.syscmds(cmd);
    }

    if (queryText.startsWith("-")) return "";

    let q = queryText + ":\n" + fileData;
    if (state.maxInputTokens > 0 && q.length > state.maxInputTokens) {
      q = q.slice(0, state.maxInputTokens);
    }

    const providerMap = {
      "anthropic": providers.anthropic,
      "claude": providers.anthropic,
      "ollama": providers.ollama,
      "ollamacloud": providers.ollamacloud,
      "openai": providers.openai,
      // Add other providers as needed
    };

    const provider = providerMap[state.api];
    if (provider) {
      return provider(q, hideprompt);
    }

    return "Unknown value for 'decai -e api'. Use r2ai, claude, ollama, ollamacloud, hf, openapi, openapi2 or openai";
  }

  // Command handlers
  const commands = {
    help: () => {
      const msg = (m) => console.error(" " + COMMAND + " " + m);
      console.error("Usage: " + COMMAND + " (-h) ...");
      msg("-a [query] - solve query with auto mode");
      msg("-d [f1 ..] - decompile given functions");
      msg("-dd [..]   - same as above, but ignoring cache");
      msg("-dD [query]- decompile current function with given extra query");
      msg("-dr        - decompile function and its called ones (recursive)");
      msg("-e         - display and change eval config vars");
      msg("-h         - show this help");
      msg("-H         - help setting up r2ai");
      msg("-i [f] [q] - include given file and query");
      msg("-k         - list API key status");
      msg("-m [model] - use -m? or -e model=? to list the available models");
      msg("-n         - suggest better function name");
      msg("-q [text]  - query language model with given text");
      msg("-Q [text]  - query on top of the last output");
      msg("-r [prompt]- change role prompt (same as: decai -e prompt)");
      msg("-R         - reset role prompt to default prompt");
      msg("-s         - function signature");
      msg("-v         - show local variables");
      msg("-V         - find vulnerabilities");
      msg("-x[*]      - eXplain current function (-x* for r2 script)");
    },

    decompile: (args, extraQuery, useCache, recursiveCalls) => {
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
        for (let addr of funcs.split(/\n/g)) {
          context += r2.cmd("pdc@" + addr);
        }
        r2.cmd("s " + at);
      }

      const appendQuery = extraQuery ? " " + args : "";
      const origColor = r2.cmd("e scr.color");
      
      try {
        args = args.slice(2).trim();
        let count = 0;
        let text = "";
        
        if (state.contextFile !== "" && r2.cmd2("test -f " + state.contextFile).value === 0) {
          text += "## Context:\n[START]\n" + r2.cmd("cat " + state.contextFile) + "\n[END]\n";
        }

        r2.cmd("e scr.color=0");
        let body = "## Before:\n";
        
        for (const c of state.commands.split(",")) {
          if (c.trim() === "") continue;
          
          const oneliner = (extraQuery || args.trim().length === 0) ? c : c + "@@= " + args;
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
          const dpipe = state.decopipe[state.decopipe.default];
          const origModel = state.model;
          let code = text + body;
          
          for (var dp of dpipe.pipeline) {
            if (dp.model) state.model = dp.model;
            const query = dp.query + ". " + dpipe.globalQuery;
            out = r2ai(query, code, true);
            if (state.debug) {
              console.log("QUERY\n", query, "\nINPUT\n", code, "\nOUTPUT\n", out);
            }
            code = out;
          }
          out = code;
        } else {
          const query = appendQuery;
          text += body + context;
          out = r2ai(query, text);
          state.lastOutput = out;
        }

        if (useCache && out.length > 1) {
          r2.call("ano=base64:" + utils.b64(out));
        }

        if (out.startsWith("```")) {
          out = out.replace(/```.*\n/, "").replace(/```$/, "");
        }

        return out.trim();
      } catch (e) {
        r2.cmd("e scr.color=" + origColor);
        console.error(e, e.stack);
      }
    },

    explain: () => {
      const origColor = r2.cmd("e scr.color");
      r2.cmd("e scr.color=0");
      const hints = "[START]" + state.commands.split(",").map(r2.cmd).join("\n") + "[END]";
      r2.cmd("e scr.color=" + origColor);
      
      const res = r2ai(
        "Analyze function calls, references, comments and strings, loops and ignore registers and memory accesses. Explain the purpose of this function in a single short sentence. /no_think Do not introduce or argue the response, translation of the explanation in " + state.humanLanguage,
        hints,
        true
      );
      
      const lines = res.trim().split(/\n/g);
      return lines[lines.length - 1].trim();
    },

    signature: () => {
      const tmp = state.language;
      const code = r2.cmd("afv;pdc");
      state.language = "C";
      
      let out = "'afs " + r2ai(
        "analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the return. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",
        code
      );
      
      let brace = out.indexOf("{");
      if (brace !== -1) {
        out = out.substring(0, brace);
      }
      
      state.language = tmp;
      return out;
    },

    auto: (queryText) => {
      const replies = [];
      
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
          const o = JSON.parse(utils.trimJson(utils.trimDown(utils.filterResponse(out))));
          
          if (o.action === "r2cmd" || o.action === "response" || o.action == o.command) {
            const ocmd = o.command;
            
            if (o.reason) {
              console.log("[r2cmd] Reasoning: " + o.reason);
              if (state.tts) {
                r2.syscmd("pkill say");
                r2.syscmd("say -v Alex -r 250 '" + o.reason.replace(/'/g, "") + "' &");
              }
            }
            
            console.log("[r2cmd] Action: " + o.description);
            console.log("[r2cmd] Command: " + ocmd);
            
            let cmd = ocmd;
            if (!state.yolo) {
              cmd = commands.autoRepl(ocmd);
            }
            
            console.log("[r2cmd] Running: " + cmd);
            const obj = r2.cmd2(cmd);
            const logs = obj.logs ? obj.logs.map(x => x.type + ": " + x.message).join("\n") : "";
            const res = (obj.res + logs).trim();
            
            console.log(res);
            const cleanRes = utils.trimAnsi(res);
            
            if (state.debug) {
              console.log("<r2output>\n", cleanRes, "\n<(r2output>");
            }
            
            replies.push(JSON.stringify({
              action: "response",
              command: cmd,
              description: o.description,
              response: cleanRes
            }));
            
          } else if (o.action === "reply") {
            console.log("Done\n", o.response);
            break;
          } else {
            console.log("Unknown response\n", JSON.stringify(out));
          }
        } catch (e) {
          const response = out.indexOf('response": "');
          if (response !== -1) {
            const res = out.slice(response + 12)
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
    },

    autoRepl: (ocmd) => {
      while (true) {
        const cmd = r2.cmd("'?ie Tweak command? ('?' for help)").trim();
        
        if (cmd == "q!") {
          console.error("Break!");
          break;
        }
        if (cmd == "?") {
          commands.autoHelp();
          continue;
        } else if (cmd.startsWith(":")) {
          console.log(r2.cmd(cmd.slice(1)));
          continue;
        } else if (cmd.startsWith("-e")) {
          main(cmd);
          continue;
        } else if (cmd == "!") {
          return "?e do NOT execute '" + ocmd + "' again, continue without it";
        } else if (cmd.startsWith("!")) {
          console.log(r2.syscmd(cmd.slice(1)));
          continue;
        } else if (cmd == "q") {
          return "?e All data collected!. Do not call more commands, reply the solutions";
        } else if (!cmd) {
          return ocmd;
        } else {
          const comment = cmd.indexOf("#");
          if (comment !== -1) {
            const command = cmd.slice(0, comment).trim();
            // o.description = cmd.slice(comment + 1).trim(); // TODO: update vdb with that command
            return command;
          }
          return cmd;
        }
      }
      return ocmd;
    },

    autoHelp: () => {
      console.log(" '!'     do not run this command");
      console.log(" '!c'    run system command");
      console.log(" 'q'     to quit auto and try to solve");
      console.log(" 'q!'    quit auto without solving");
      console.log(" 'c # C' use given command with comment");
      console.log(" ':c'    run r2 command without feeding auto");
      console.log(" '-e'    set decai configuration variables");
    }
  };

  // Main command processor
  function main(args) {
    if (args === "") {
      commands.help();
      return true;
    }

    if (!args.startsWith("-")) {
      commands.help();
      return true;
    }

    let output = "";
    const flag = args[1];
    
    switch (flag) {
      case "H":
        console.log(HELP_TEXT.decai);
        break;
        
      case "a":
        commands.auto(args.slice(2).trim());
        break;
        
      case "m":
        const arg0 = args.slice(2).trim();
        if (arg0 === "=") {
          config.eval("model=");
        } else if (arg0) {
          config.eval("model=" + arg0);
        } else {
          config.eval("model");
        }
        break;
        
      case "n":
      case "f":
        output = r2.cmd("axff~$[3]");
        const considerations = r2.cmd("fd.").trim()
          .split(/\n/)
          .filter(x => !x.startsWith("secti"))
          .join(",");
        
        output = r2ai(
          "give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: " + considerations,
          output
        ).trim();
        output += " @ " + r2.cmd("?v $FB").trim();
        break;
        
      case "v":
        output = r2.cmd("afv;pdc");
        output = r2ai(
          "guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",
          output
        );
        break;
        
      case "i":
        const parts = args.slice(2).trim().split(/ /g, 2);
        if (parts.length === 2) {
          const file = parts[0];
          const query = parts[1];
          const fileData = r2.cmd("cat " + file);
          console.log(r2ai(query, fileData, true));
        } else {
          console.log("Use: decai -i [file] [query ...]");
        }
        break;
        
      case "r":
        const prompt = args.slice(2).trim();
        if (prompt) {
          state.prompt = prompt;
        } else {
          console.log(state.prompt);
        }
        break;
        
      case "R":
        state.prompt = DEFAULT_PROMPT;
        break;
        
      case "s":
        output = commands.signature();
        break;
        
      case "V":
        output = r2ai(
          "find vulnerabilities, dont show the code, only show the response, provide a sample exploit",
          state.lastOutput
        );
        break;
        
      case "k":
        apiKeys.list();
        break;
        
      case "e":
        const evalArg = args.slice(2).trim();
        if (evalArg) {
          config.eval(evalArg);
        } else {
          config.listAll();
        }
        break;
        
      case "q":
        try {
          output = r2ai(args.slice(2).trim(), null, true);
        } catch (e) {
          console.error(e, e.stack);
        }
        break;
        
      case "Q":
        output = r2ai(args.slice(2).trim(), state.lastOutput);
        break;
        
      case "x":
        output = commands.explain();
        if (args[2] === "*" || args[2] === "r") {
          output = "'CC " + output;
        }
        break;
        
      case "d":
        if (args[2] === "r") {
          output = commands.decompile(args.slice(2), true, state.cache, true);
        } else if (args[2] === "d") {
          output = commands.decompile(args, false, false, false);
        } else if (args[2] === "D") {
          output = commands.decompile(args, true, false, false);
        } else {
          output = commands.decompile(args, false, state.cache, false);
        }
        break;
        
      default:
        commands.help();
        break;
    }

    if (output) {
      r2.log(output);
    }
    return true;
  }

  // Plugin registration
  r2.unload("core", COMMAND);
  r2.plugin("core", function () {
    function coreCall(cmd) {
      if (cmd.startsWith(COMMAND)) {
        const args = cmd.slice(COMMAND.length).trim();
        return main(args);
      }
      return false;
    }

    return {
      "name": COMMAND,
      "license": "MIT", 
      "desc": "r2 decompiler based on r2ai",
      "call": coreCall
    };
  });
})();
