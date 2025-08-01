(function () {
  const decaiHelp = `
# Using Decai

Decai is the radare2 plugin for decompiling functions with the help of language models.
By default uses a local ollama server, but can you can pick any other service by using 'decai -e api=?'.

[0x00000000]> decai -e api=?
r2ai claude deepseek gemini hf mistral ollama openapi openai vllm xai

## Using Ollama

* Visit https://ollama.com to install it.
* Download the model of choice: 'ollama run llama3.3'
* Configure decai to use the given model with: 'decai -e model=?'

These are the most recommended models for decompiling in local:

* hhao/qwen2.5-coder-tools:latest (18GB of ram)
* hhao/qwen2.5-coder-tools:32b (24GB of ram required)

## Common Options
* 'decai -e baseurl=<url>' override default host and port for API endpoint (e.g., 'http://localhost:11434')

* 'decai -e deterministic=true' to remove randomness from decompilation responses
* 'decai -e lang=Python' to output the decompilation in Python instead of C
* 'decai -e hlang=Catalan' to add comments or explanations in that language (instead of English)
* 'decai -e cmds=pdd,pdg' use r2dec and r2ghidra instead of r2's pdc as input for decompiling
* 'decai -e prompt=..' default prompt must be fine for most models and binaries, feel free to tweak it

## API Keys

Remove services like OpenAI, Mistral, Anthropic, Grok, Gemini, .. require API keys to work.

See 'decai -k' to list the status of available APIkeys

Decai will pick them from the environment or the config files in your home:

* echo KEY > ~/.r2ai.openai-key
* export OPENAI_API_KEY=...

## Using the R2AI Server:

Install r2ai or r2ai-server with r2pm:

[0x0000000]> decai -e api=r2ai
[0x0000000]> r2pm -ci r2ai

Choose one of the recommended models (after r2pm -r r2ai):

* -m ibm-granite/granite-20b-code-instruct-8k-GGUF
* -m QuantFactory/granite-8b-code-instruct-4k-GGUF
* -m TheBloke/Mistral-7B-Instruct-v0.2-GGUF

Start the webserver:

$ r2pm -r r2ai-server -l r2ai -m granite-8b-code-instruct-4k.Q2_K

## Permanent Settings

You can write your custom decai commands in your ~/.radare2rc file.

`;
  const autoPrompt = `
# Radare2 Auto Mode

Use function calling to execute radare2 commands in order to resolve the user request defined in the "User Prompt" section, analyze the responses attached in the "Command Results" section.

## Function Calling

Respond ONLY using plain JSON. Process user query and decide which function calls are necessary to solve the task.

1. Analyze the user request to determine if we need to run commands to extend the knowledge and context of the problem.
2. If function call is needed, construct the JSON like this:
 - Fill the "action" key with the "r2cmd" value.
 - Specify the "command" as a string.
 - Optionally, provide a "reason" and "description"
3. If the answer can be provided and no more function calls are required:
 - Use the key "action": "reply".
 - Include "response" with the direct answer to the user query.

Return the result as a JSON object.

### Sample Function Calling Communication

Command Results: already performed actions with their responses
User Prompt: "Count how many functions we have here."
Response:
{
    "action": "r2cmd",
    "command": "aflc",
    "description": "Count functions"
    "reason": "Evaluate if the program is analyzed before running aaa"
}

## Rules

Use radare2 to resolve user requests.

* Explain each step in the "reason" field of the JSON.
* Follow the initial analysis instructions.
* Output only valid JSON as specified.
* Decompile and inspect functions, starting from main.
* Run only the needed commands to gather info.
* Use "@ (address|symbol)" to seek temporarily.
* Output should be a verbose markdown report.
* Use "sym." or "fcn." prefixes if "pdc" is empty.
* If a seek fails, use "f~name" to find the symbol's address.

### Initial Analysis

1. Run "aflc" to count the number of functions
2. If the output of "aflc" is "0" run "aaa" once, then "aflc" again
3. Run only one command at a time (do not use ";")

### Special cases

* On Swift binaries run "/az" to find assembly constructed strings
* For better function decompilation results use "pdd"

### Planing Steps

1. Rephrase the user request into clear tasks.
2. Review available commands and choose only what's needed.
3. Follow the task list step-by-step.
4. Avoid redundant or repeated actions.
5. Minimize token use by acting efficiently.
6. Solve the problem quickly and accurately.

## Functions or Commands

* "i" : get information from the binary
* "is" : list symbols
* "izqq" : show all strings inside the binary
* "aflm" : list all functions and their calls
* "aflc" : count the amount of functions analyzed
* "ies" : show entrypoints symbols
* "pdsf" : show strings and function names referenced in function
* "iic" : classify imported symbols (network, format string, thread unsafe, etc)
* "pdc" : decompile function
* "iiq" : enumerate the imported symbols
* "izqq~http:,https:" : filter strings for http and https network urls
* "ilq" : Enumerate libraries and frameworks

`;

  let decopipe = { use: false };
  const command = "decai";
  let decaiHost = "http://localhost";
  let decaiPort = "11434";
  // base URL overrides host and port when provided (e.g. "http://example.com:8000")
  let decaiBaseurl = "";
  let decaiApi = "ollama"; // uses /cmd endpoint
  let decaiPipeline = "";
  let decaiCommands = "pdc";
  let decaiYolo = false;
  let decaiTts = false;
  let decaiLanguage = "C";
  let decaiHumanLanguage = "English";
  let decaiDeterministic = true;
  let decaiDebug = false;
  let decaiThink = -1; // -1 = nothing, 0 = nothink, 1 = think, 2 = show reasoning
  let useFiles = false; // use filesystem instead of args when calling curl, supports longer context
  let decaiContextFile = "";
  let decaiModel = "";
  let lastOutput = "";
  let decaiCache = false;
  let maxInputTokens = -1; // -1 = disabled i.e fileData is not truncated up to this limit
  const defaultPrompt =
    "Transform this pseudocode and respond ONLY with plain code (NO explanations, comments or markdown), Change 'goto' into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and strings from comments like 'string:', Reduce lines of code and fit everything in a single function, Remove all dead code";
  // const defaultPrompt = "Rewrite this function following these rules:\n* Replace goto statements with structured control flow (if/else/for/while).\n* Simplify logic and remove unused code as much as possible.\n* Rename variables to be more meaningful.\n* Extract and inline function arguments and string values from comments like 'string:'.\n* Strictly return only the transformed code, without any explanations, markdown, or extra formatting."
  let decaiPrompt = defaultPrompt;

  function tmpdir(path) {
    const dir = r2.cmd("-e dir.tmp").trim() ?? ".";
    return dir + "/" + path;
  }
  function fileExist(path) {
    if (r2.cmd2("test -h").logs[0].message.indexOf("-fdx") !== -1) {
      // r2 is old and it doesn't support "test -v"
      return true;
    }
    return r2.cmd("'test -vf " + path).startsWith("found");
  }
  function getApiKey(provider, envvar) {
    const keyEnv = r2.cmd("'%" + envvar).trim();
    if (keyEnv.indexOf("=") === -1 && keyEnv !== "") {
      return [keyEnv.trim(), null, "env"];
    }
    const keyPath = "~/.r2ai." + provider + "-key";
    if (fileExist(keyPath)) {
      const keyFile = r2.cmd("'cat " + keyPath);
      if (keyFile === "") {
        return [null, "Cannot read " + keyPath, "no"];
      }
      return [keyFile.trim(), null, "file"];
    }
    return [null, "Not available", "nope"];
  }

  function listApiKeys() {
    const providers = {
      "mistral": "MISTRAL_API_KEY",
      "anthropic": "ANTHROPIC_API_KEY",
      "huggingface": "HUGGINGFACE_API_KEY",
      "openai": "OPENAI_API_KEY",
      "gemini": "GEMINI_API_KEY",
      "deepseek": "DEEPSEEK_API_KEY",
      "xai": "XAI_API_KEY",
    };
    for (const key of Object.keys(providers)) {
      const what = getApiKey(key, providers[key])[2];
      console.log(what, "\t", key);
    }
  }

  function curlGet(url, headers) {
    const heads = headers.map((x) => {
      return '-H "' + x + '"';
    }).join(" ");
    const curlc = `curl -s ${url} ${heads} -H "Content-Type: application/json"`;
    return JSON.parse(r2.syscmds(curlc));
  }

  function curlPost(url, headers, payload) {
    const heads = headers.map((x) => {
      return '-H "' + x + '"';
    }).join(" ");
    function curlArgs(url, heads, payload) {
      // Escape single quotes in payload to prevent command injection
      const escapedPayload = payload.replace(/'/g, "'\\''")
      const curlc =
        `curl -s '${url}' ${heads} -d '${escapedPayload}' -H "Content-Type: application/json"`;
      debug.log(curlc);
      return r2.syscmds(curlc);
    }
    function curlFile(url, heads, payload) {
      const tmpfile = r2.fdump(payload);
      const curlc =
        `curl -s '${url}' ${heads} -d '@${tmpfile}' -H "Content-Type: application/json"`;
      console.log(curlc);
      debug.log(curlc);
      const output = r2.syscmd(curlc);
      r2.syscmd("rm " + tmpfile);
      return output;
    }
    const method = useFiles ? curlFile : curlArgs;
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

  const padRight = (str, length) =>
    str + " ".repeat(Math.max(0, length - str.length));

  function listClaudeModels() {
    const key = getApiKey("anthropic", "ANTHROPIC_API_KEY");
    if (key[1]) {
      throw new Error(key[1]);
    }
    const headers = ["x-api-key: " + key[0], "anthropic-version: 2023-06-01"];
    const response = curlGet("https://api.anthropic.com/v1/models", headers);
    return response.data.map((model) => model.id).join("\n");
  }
  function listMistralModels() {
    const key = getApiKey("mistral", "MISTRAL_API_KEY");
    if (key[1]) {
      throw new Error(key[1]);
    }
    const headers = ["Authorization: Bearer " + key[0]];
    const response = curlGet("https://api.mistral.ai/v1/models", headers);
    const uniqByName = (arr) =>
      arr.filter((obj, i, self) =>
        self.findIndex((o) => o.name === obj.name) === i
      );
    return uniqByName(response.data).map((model) =>
      [
        padRight(model.name, 30),
        padRight("" + model.max_context_length, 10),
        model.description,
      ].join(" ")
    ).join("\n");
  }

  function listModelsFor(decaiApi) {
    switch (decaiApi) {
      case "ollama":
      case "openapi":
        console.log(openApiListModels()); // || "!ollama ls"
        break;
      case "groq":
        console.log("meta-llama/llama-4-scout-17b-16e-instruct");
        break;
      case "openai":
        console.log("o1");
        console.log("o1-mini");
        console.log("o3");
        console.log("gpt-4.1");
        console.log("gpt-4.1-nano");
        console.log("gpt-4.1-mini");
        console.log("gpt-4-turbo");
        console.log("gpt-4o");
        console.log("gpt-4o-mini");
        console.log("gpt-4.5-preview");
        break;
      case "gemini":
        console.log("gemini-2.0-flash");
        console.log("gemini-2.0-flash-lite");
        console.log("gemini-1.5-pro");
        console.log("gemini-1.5-flash");
        break;
      case "claude":
      case "anthropic":
        console.log(listClaudeModels());
        console.log("claude-3-5-sonnet-20241022");
        console.log("claude-3-7-sonnet-20250219");
        console.log("claude-opus-4-20250514");
        console.log("claude-sonnet-4-20250514");
        break;
      case "xai":
        console.log("grok-2");
        console.log("grok-beta");
        // console.log("grok-3");
        break;
      case "mistral":
        try {
          console.log(listMistralModels());
        } catch (e) {
          console.error(e, e.stack);
        }
        console.log("codestral-latest");
        break;
    }
  }
  const config = {
    "pipeline": {
      get: () => decaiPipeline,
      set: () => {
        decaiPipeline = v;
        try {
          decopipe = JSON.parse(r2.cmd("cat " + v));
        } catch (e) {
          console.error(e);
        }
      },
    },
    "model": {
      get: () => decaiModel,
      set: (v) => {
        if (v === "?") {
          listModelsFor(decaiApi);
        } else {
          decaiModel = v.trim();
        }
      },
    },
    "deterministic": {
      get: () => decaiDeterministic,
      set: (v) => {
        decaiDeterministic = v === "true" || v === "1";
      },
    },
    "files": {
      get: () => useFiles,
      set: (v) => {
        useFiles = v === "true";
      },
    },
    "think": {
      get: () => decaiThink,
      set: (v) => {
        decaiThink = (v === "true") ? 1 : (v === "false") ? 0 : +v;
      },
    },
    "debug": {
      get: () => decaiDebug,
      set: (v) => {
        decaiDebug = v === "true" || v === "1";
      },
    },
    "api": {
      get: () => decaiApi,
      set: (v) => {
        if (v === "?") {
          console.error(
            "r2ai\nclaude\ndeepseek\ngemini\nhf\nmistral\nollama\nopenapi\nopenapi2\nopenai\nvllm\nxai\n",
          );
        } else {
          decaiApi = v;
        }
      },
    },
    "lang": {
      get: () => decaiLanguage,
      set: (v) => {
        decaiLanguage = v;
      },
    },
    "hlang": {
      get: () => decaiHumanLanguage,
      set: (v) => {
        decaiHumanLanguage = v;
      },
    },
    "cache": {
      get: () => decaiCache,
      set: (v) => {
        decaiCache = v === "true" || v == 1;
      },
    },
    "cmds": {
      get: () => decaiCommands,
      set: (v) => {
        decaiCommands = v;
      },
    },
    "tts": {
      get: () => decaiTts,
      set: (v) => {
        decaiTts = v === "true" || v == 1;
      },
    },
    "yolo": {
      get: () => decaiYolo,
      set: (v) => {
        decaiYolo = v === "true" || v == 1;
      },
    },
    "prompt": {
      get: () => decaiPrompt,
      set: (v) => {
        decaiPrompt = v;
      },
    },
    "ctxfile": {
      get: () => decaiContextFile,
      set: (v) => {
        decaiContextFile = v;
      },
    },
    "baseurl": {
      get: () => decaiBaseurl,
      set: (v) => { decaiBaseurl = v; },
    },
    "maxtokens": {
      get: () => maxInputTokens,
      set: (v) => {
        maxInputTokens = v;
      },
    },
  };

  function decaiEval(arg) {
    const [k, v] = arg.split("=");
    if (Object.keys(config).indexOf(k) === -1) {
      console.error("Unknown config key");
    } else if (typeof v !== "undefined") {
      config[k].set(v);
    } else {
      console.log(config[k].get());
    }
  }
  function buildQuery(msg, hideprompt) {
    if (+decaiThink >= 0) {
      if (+decaiThink === 0) {
        msg +=
          ' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".';
        msg += " /no_think";
      } else if (+decaiThink > 0) {
        msg =
          "Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer." +
          msg;
      }
    }
    return hideprompt ? msg : decaiPrompt + languagePrompt() + msg;
  }
  function filterResponse(msg) {
    if (decaiThink !== 2) {
      msg = msg.replace(/<think>[\s\S]*?<\/think>/gi, "");
    }
    return msg.split("\n").filter((line) => !line.trim().startsWith("```"))
      .join("\n");
  }
  function usage() {
    const msg = (m) => console.error(" " + command + " " + m);
    console.error("Usage: " + command + " (-h) ...");
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
    msg(
      "-m [model] - use -m? or -e model=? to list the available models for '-e api='",
    );
    msg("-n         - suggest better function name");
    msg("-q [text]  - query language model with given text");
    msg("-Q [text]  - query on top of the last output");
    msg("-r [prompt]- change role prompt (same as: decai -e prompt)");
    msg("-R         - reset role prompt to default prompt");
    msg("-s         - function signature");
    msg("-v         - show local variables");
    msg("-V         - find vulnerabilities");
    msg("-x[*]      - eXplain current function (-x* for r2 script)");
  }
  function r2aiAnthropic(msg, hideprompt) {
    const claudeKey = r2.cmd("'cat ~/.r2ai.anthropic-key").trim();
    const claudeModel = (decaiModel.length > 0)
      ? decaiModel
      : "claude-3-7-sonnet-20250219";
    if (claudeKey === "") {
      return "Cannot read ~/.r2ai.anthropic-key";
    }
    const query = buildQuery(msg, hideprompt);
    const object = {
      model: claudeModel,
      max_tokens: 5128,
      messages: [
        {
          "role": "user",
          "content": query,
        },
      ],
    };
    if (decaiDeterministic) {
      object.temperature = 0;
      object.top_p = 0;
      object.top_k = 1;
    }
    const payload = JSON.stringify(object);
    const url = "https://api.anthropic.com/v1/messages";
    const headers = [
      "anthropic-version: 2023-06-01",
      "x-api-key: " + claudeKey,
    ];
    const res = curlPost(url, headers, payload);
    try {
      return filterResponse(res.content[0].text);
    } catch (e) {
      return "ERROR: " + res.error.message;
    }
  }

  function r2aiHuggingFace(msg, hideprompt) {
    const key = getApiKey("huggingface", "HUGGINGFACE_API_KEY");
    if (key[1]) {
      throw new Error(key[1]);
    }
    let hfModel = decaiModel ?? "deepseek-ai/DeepSeek-Coder-V2-Instruct";
    const query = buildQuery(msg, hideprompt);
    const payload = JSON.stringify({
      inputs: query,
      parameters: {
        max_new_tokens: 5128,
      },
    });
    const url = "https://api-inference.huggingface.co/models/" + hfModel;
    const headers = ["Authorization: Bearer " + key[0]];
    const o = curlPost(url, headers, payload);
    if (o.error) {
      return "ERROR: " + o.error;
    }
    return o.generated_text;
  }

  function r2aiDeepseek(msg, hideprompt) {
    const deepseekKey = r2.cmd("'cat ~/.r2ai.deepseek-key").trim();
    if (deepseekKey === "") {
      return "Cannot read ~/.r2ai.deepseek-key";
    }
    const deepseekModel = (decaiModel.length > 0)
      ? decaiModel
      : "deepseek-coder";
    const query = buildQuery(msg, hideprompt);
    const payload = JSON.stringify({
      model: deepseekModel,
      messages: [{ role: "user", content: query }],
    });
    const curlcmd =
      `curl -X POST "https://api.deepseek.com/v1/chat" -H "Authorization: Bearer ${deepseekKey}" -H "Content-Type: application/json" -d '${payload}'`; // .replace(/\n/g, "");
    debug.log(curlcmd);
    const res = r2.syscmds(curlcmd);
    try {
      return JSON.parse(res).choices[0].message.content;
    } catch (e) {
      console.error(e);
      console.log(res);
    }
    return "error invalid response";
  }
  function r2aiGroq(msg, hideprompt) {
    const groqKey = r2.cmd("'cat ~/.r2ai.groq-key").trim();
    if (groqKey === "") {
      return "Cannot read ~/.r2ai.groq-key";
    }
    const groqModel = (decaiModel.length > 0)
      ? decaiModel
      : "meta-llama/llama-4-scout-17b-16e-instruct";
    const query = buildQuery(msg, hideprompt);
    const payload = JSON.stringify({
      model: groqModel,
      messages: [{ role: "user", content: query }],
    });
    const curlcmd =
      `curl -X POST "https://api.groq.com/openai/v1/chat/completions" -H "Authorization: Bearer ${groqKey}" -H "Content-Type: application/json" -d '${payload}'`; // .replace(/\n/g, "");
    debug.log(curlcmd);
    const res = r2.syscmds(curlcmd);
    try {
      return JSON.parse(res).choices[0].message.content;
    } catch (e) {
      console.error(e);
      console.log(res);
    }
    return "error invalid response";
  }
  function r2aiGemini(msg, hideprompt) {
    const geminiKey = r2.cmd("'cat ~/.r2ai.gemini-key").trim();
    if (geminiKey === "") {
      return "Cannot read ~/.r2ai.gemini-key";
    }
    const geminiModel = (decaiModel.length > 0)
      ? decaiModel
      : "gemini-1.5-flash";
    const query = buildQuery(msg, hideprompt);
    const object = { contents: [{ parts: [{ text: query }] }] };
    if (decaiDeterministic) {
      object.generationConfig = {
        "temperature": 0.0,
        "topP": 1.0,
        "topK": 1,
      };
    }
    const payload = JSON.stringify(object);
    const url =
      `https://generativelanguage.googleapis.com/v1beta/models/${geminiModel}:generateContent?key=${geminiKey}`;
    const res = curlPost(url, [], payload);
    try {
      return res.candidates[0].content.parts[0].text;
    } catch (e) {
      console.error(e);
      console.log(res);
    }
    return "error invalid response";
  }
  function r2aiOpenAI(msg, hideprompt) {
    const openaiKey = r2.cmd("'cat ~/.r2ai.openai-key").trim();
    if (openaiKey === "") {
      return "Cannot read ~/.r2ai.openai-key";
    }
    const openaiModel = (decaiModel.length > 0) ? decaiModel : "gpt-4-turbo"; // "o4-mini"; // o-2024-11-20";
    const query = buildQuery(msg, hideprompt);
    const object = {
      model: openaiModel,
      messages: [
        // { "role": "system", "content": hideprompt? decaiPrompt: "" },
        { "role": "user", "content": query },
      ],
    };
    if (decaiDeterministic) {
      if (!openaiModel.startsWith("o4") && !openaiModel.startsWith("o1")) {
        object.temperature = 0;
        object.top_p = 0;
      }
      object.frequency_penalty = 0;
      object.presence_penalty = 0;
    }
    const payload = JSON.stringify(object);
    const url = (decaiBaseurl? decaiBaseurl: "https://api.openai.com/v1") + "/chat/completions";
    const headers = ["Authorization: Bearer " + openaiKey];
    const res = curlPost(url, headers, payload);
    try {
      return filterResponse(res.choices[0].message.content);
    } catch (e) {
      console.error(e, e.stack);
      console.log(JSON.stringify(res, false, 2));
    }
    return "error invalid response";
  }
  function r2aiMistral(msg, hideprompt) {
    const mistralKey = r2.cmd("'cat ~/.r2ai.mistral-key").trim();
    if (mistralKey === "") {
      return "Cannot read ~/.r2ai.mistral-key";
    }
    const model = decaiModel ? decaiModel : "codestral-latest";
    const query = buildQuery(msg, hideprompt);
    const object = {
      stream: false,
      model: model,
      messages: [
        {
          role: "user",
          content: query,
        },
      ],
    };
    if (decaiDeterministic) {
      object.n = 1;
      object.top_p = 0.001;
      object.random_seed = 1;
      object.temperature = 0.001;
    }
    const payload = JSON.stringify(object);
    const url = "https://api.mistral.ai/v1/chat/completions";
    const headers = [
      "Accept: application/json",
      "Authorization: Bearer " + mistralKey,
    ];
    const res = curlPost(url, headers, payload);
    try {
      return filterResponse(res.choices[0].message.content);
    } catch (e) {
      console.error(e, e.stack);
      console.error("ERROR:" + JSON.stringify(res, null, 2));
      console.error("ERROR:" + res.detail[0].msg);
    }
  }
  const debug = {
    log: (msg) => {
      if (decaiDebug) {
        console.log(msg);
      }
    },
  };
  function languagePrompt() {
    return "\n.Translate the code into " + decaiLanguage +
      " programming language\n";
  }
  function r2aiOllama(msg, hideprompt) {
    const model = decaiModel ? decaiModel : "qwen2.5-coder:latest";
    const query = buildQuery(msg, hideprompt);
    const object = {
      stream: false,
      model: model,
      messages: [{ role: "user", content: query }],
    };
    if (decaiDeterministic) {
      object.options = {
        repeat_last_n: 0,
        top_p: 0.0,
        top_k: 1.0,
        temperature: 0.0,
        repeat_penalty: 1.0,
        seed: 123,
      };
    }
    const payload = JSON.stringify(object);
    debug.log(payload);
    const base = decaiBaseurl || (decaiHost + ":" + decaiPort);
    const url = base + "/api/chat";
    const res = curlPost(url, [], payload);
    try {
      return filterResponse(res.message.content);
    } catch (e) {
      if (res.error.indexOf("try pulling")) {
        const modelName = res.error.split(/"/g)[1];
        res.error += "\n!ollama run " + modelName;
      }
      return "ERROR: " + res.error;
    }
  }
  function r2aiOpenAPI(msg, hideprompt) {
    const query = buildQuery(msg, hideprompt);
    const payload = JSON.stringify({ "prompt": query });
    const base = decaiBaseurl || (decaiHost + ":" + decaiPort);
    const url = `${base}/api/generate`;
    const res = curlPost(url, [], payload);
    try {
      return res.content;
    } catch (e) {
      console.error(e);
      console.log(res);
    }
    return "error invalid response";
  }
  function openApiListModels(msg, hideprompt) {
    const base = decaiBaseurl || (decaiHost + ":" + decaiPort);
    const curlcmd = `curl -s ${base}/api/tags`;
    const res = r2.syscmds(curlcmd);
    try {
      const models = JSON.parse(res).models;
      const out = [];
      for (const model of models) {
        out.push(model.name);
      }
      return out.join("\n");
    } catch (e) {
      console.error(e);
      console.log(res);
    }
    return "error invalid response";
  }
  function r2aiXai(msg, hideprompt) {
    const xaiKey = r2.cmd("'cat ~/.r2ai.xai-key").trim();
    if (xaiKey === "") {
      return "Cannot read ~/.r2ai.xai-key";
    }
    const xaiModel = (decaiModel.length > 0) ? decaiModel : "grok-beta";
    const query = buildQuery(msg, hideprompt);
    const payload = JSON.stringify({
      messages: [{ role: "user", "content": query }],
      "model": xaiModel,
      stream: false,
    });
    const url = "https://api.x.ai/v1/chat/completions";
    const headers = ["Authorization: Bearer " + xaiKey];
    const res = curlPost(url, headers, payload);
    try {
      return res.choices[0].message.content;
    } catch (e) {
      console.error(e);
      console.log(res);
    }
    return "error invalid response";
  }
  function r2aiVLLM(msg, hideprompt) {
    const query = buildQuery(msg, hideprompt);
    const payload = JSON.stringify({
      "prompt": query,
      "model": "lmsys/vicuna-7b-v1.3",
    });
    const base = decaiBaseurl || (decaiHost + ":8000");
    const curlcmd = `curl -s ${base}/v1/completions -H "Content-Type: application/json" -d '${payload}'`;
    debug.log(curlcmd);
    const res = r2.syscmds(curlcmd);
    try {
      return JSON.parse(res).choices[0].text;
    } catch (e) {
      console.error(e);
      console.log(res);
    }
    return "error invalid response";
  }
  function r2aiOpenAPI2(msg, hideprompt) {
    const query = buildQuery(msg, hideprompt);
    const payload = JSON.stringify({
      "prompt": query,
      "model": "qwen2.5_Coder_1.5B_4bit",
    });
    const base = decaiBaseurl || (decaiHost + ":" + decaiPort);
    const curlcmd = `curl -s ${base}/api/generate -H "Content-Type: application/json" -d '${payload}'`;
    debug.log(curlcmd);
    const res = r2.syscmds(curlcmd);
    try {
      return JSON.parse(res).response;
    } catch (e) {
      console.error(e);
      console.log(res);
    }
    return "error invalid response";
  }
  function decaiDecompile(args, extraQuery, useCache, recursiveCalls) {
    if (useCache) {
      const cachedAnotation = r2.cmd("anos").trim();
      if (cachedAnotation.length > 0) {
        return cachedAnotation;
      }
    }
    let context = "";
    if (recursiveCalls) {
      const at = r2.cmd("s");
      context += "## Context functions:\n";
      // pdc@@=`axff~^C[2]~$$`
      const funcs = r2.cmdAt("axff~^C[2]~$$", at);
      // const funcs = r2.cmdAt('axff~[2]', at);
      for (let at of funcs.split(/\n/g)) {
        context += r2.cmd("pdc@" + at);
      }
      r2.cmd("s " + at);
    }
    let out = "";
    const appendQuery = extraQuery ? " " + args : "";
    const origColor = r2.cmd("e scr.color");
    try {
      args = args.slice(2).trim();
      const file = tmpdir(".pdc.txt");
      r2.call("rm .pdc.txt");
      r2.call("rm " + file);
      r2.cmd("echo > " + file);
      let count = 0;
      let text = "";
      if (decaiContextFile !== "") {
        if (r2.cmd2("test -f " + decaiContextFile).value === 0) {
          text += "## Context:\n";
          text += "[START]\n";
          text += r2.cmd("cat " + decaiContextFile);
          text += "[END]\n";
        }
      }
      r2.cmd("e scr.color=0");
      let body = "## Before:\n";
      for (const c of decaiCommands.split(",")) {
        if (c.trim() === "") {
          continue;
        }
        const oneliner = (extraQuery || args.trim().length === 0)
          ? c
          : c + "@@= " + args;
        const output = r2.cmd(oneliner);
        if (output.length > 5) {
          body += "Output of " + c + ":\n";
          body += "[START]\n" + output + "\n[END]\n";
          // body += "## Code from " + c + ":\n\n```c" + "\n" + output + "\n```\n";
          // body +=  output + "\n[END]\n";
          count++;
        }
      }
      body += "## After:\n";
      // body += "[START]\n";
      r2.cmd("e scr.color=" + origColor);
      if (count === 0) {
        console.error("Nothing to do.");
        return;
      }
      r2ai("-R");
      if (decopipe.use) {
        const dpipe = decopipe[decopipe.default];
        const origModel = decaiModel;
        let code = text + body;
        for (var dp of dpipe.pipeline) {
          if (dp.model) {
            decaiModel = dp.model;
          }
          const query = dp.query + ". " + dpipe.globalQuery;
          out = r2ai(query, code, true);
          if (decaiDebug) {
            console.log("QUERY");
            console.log(query);
            console.log("INPUT");
            console.log(code);
            console.log("OUTPUT");
            console.log(out);
          }
          code = out;
        }
        out = code;
      } else {
        const query = appendQuery;
        text += body;
        text += context;
        out = r2ai(query, text);
        lastOutput = out;
      }
    } catch (e) {
      r2.cmd("e scr.color=" + origColor);
      console.error(e, e.stack);
    }
    if (useCache && out.length > 1) {
      r2.call("ano=base64:" + b64(out));
    }
    if (out.startsWith("```")) {
      out = out.replace(/```.*\n/, "").replace(/```$/, "");
    }
    return out.trim();
  }
  function fileDump(fileName, fileData) {
    const d = b64(fileData);
    r2.cmd("p6ds " + d + " > " + fileName);
  }
  function trimDown(out) {
    const jsonMatch = out.match(/```json\s*([\s\S]*?)```/);
    if (jsonMatch && jsonMatch[1]) {
      out = jsonMatch[1].trim();
    }
    return out;
  }
  function trimAnsi(str) {
    return str.replace(/\x1b\[[0-9;]*m/g, "");
  }
  function trimJson(out) {
    const bob = out.indexOf("{");
    if (bob !== -1) {
      out = out.slice(bob);
    }
    const eob = out.indexOf("}");
    if (eob !== -1) {
      out = out.slice(0, eob + 1);
    }
    return out;
  }
  function decaiExplain() {
    var origColor = r2.cmd("e scr.color");
    r2.cmd("e scr.color=0");
    const hints = "[START]" + decaiCommands.split(",").map(r2.cmd).join("\n") +
      "[END]";
    r2.cmd("e scr.color=" + origColor);
    r2ai("-R");
    const res = r2ai(
      "Analyze function calls, references, comments and strings, loops and ignore registers and memory accesess. Explain the purpose of this function in a single short sentences. /no_think Do not introduce or argue the response, translation of the explanation in " +
        decaiHumanLanguage,
      hints,
      true,
    );
    const lines = res.trim().split(/\n/g);
    return lines[lines.length - 1].trim();
  }
  function decaiSignature() {
    const tmp = decaiLanguage;
    const code = r2.cmd("afv;pdc");
    decaiLanguage = "C";
    let out = "'afs " +
      r2ai(
        "analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the resturn. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",
        code,
      );
    let brace = out.indexOf("{");
    if (brace !== -1) {
      out = out.substring(0, brace);
    }
    decaiLanguage = tmp;
    return out;
  }
  function decaiAutoHelp() {
    console.log(" '!'     do not run this command");
    console.log(" '!c'    run system command");
    console.log(" 'q'     to quit auto and try to solve");
    console.log(" 'q!'    quit auto without solving");
    console.log(" 'c # C' use given command with comment");
    console.log(" ':c'    run r2 command without feeding auto");
    console.log(" '-e'    set decai configuration variables");
  }
  function decaiAutoRepl(ocmd) {
    while (true) {
      cmd = r2.cmd("'?ie Tweak command? ('?' for help)").trim();
      if (cmd == "q!") {
        console.error("Break!");
        break;
      }
      if (cmd == "?") {
        decaiAutoHelp();
        continue;
      } else if (cmd.startsWith(":")) {
        console.log(r2.cmd(cmd.slice(1)));
        continue;
      } else if (cmd.startsWith("-e")) {
        r2aidec(cmd);
        continue;
      } else if (cmd == "!") {
        cmd = "?e do NOT execute '" + ocmd +
          "' again, continue without it";
      } else if (cmd.startsWith("!")) {
        console.log(r2.syscmd(cmd.slice(1)));
      } else if (cmd == "q") {
        cmd =
          "?e All data collected!. Do not call more commands, reply the solutions";
      } else if (!cmd) {
        cmd = ocmd;
      } else {
        const comment = cmd.indexOf("#");
        if (comment !== -1) {
          const command = cmd.slice(0, comment).trim();
          o.description = cmd.slice(comment + 1).trim();
          cmd = command;
          // TODO: update vdb with that command
        }
      }
      break;
    }
    return cmd;
  }
  function decaiAuto(queryText) {
    r2ai("-R");
    let autoQuery = autoPrompt;
    const replies = [];
    while (true) {
      let q = autoPrompt;
      if (replies.length > 0) {
        q += "## Command Results\n\n";
        for (const rep of replies) {
          const rp = JSON.parse(rep);
          q += "### " + rp.command + "\n\n";
          q += "```\n";
          q += rp.response;
          q += "```\n";
        }
        // q += replies.join("\n");
      }
      q += "\n\n## User Prompt\n\n" + queryText;
      if (decaiDebug) {
        console.log("#### input");
        console.log(q);
        console.log("#### /input");
      }
      console.log("Thinking...");
      out = r2ai("", q, true);
      // out = r2ai(q, "", true);
      if (decaiDebug) {
        console.log("#### output");
        console.log(out);
        console.log("#### /output");
      }
      let myYolo = false;
      try {
        const o = JSON.parse(trimJson(trimDown(filterResponse(out))));
        if (
          o.action === "r2cmd" || o.action === "response" ||
          o.action == o.command
        ) {
          const ocmd = o.command;
          if (o.reason) {
            console.log("[r2cmd] Reasoning: " + o.reason);
            if (decaiTts) {
              r2.syscmd("pkill say");
              r2.syscmd(
                "say -v Alex -r 250 '" + o.reason.replace(/'/g, "") + "' &",
              );
            }
          }
          console.log("[r2cmd] Action: " + o.description);
          console.log("[r2cmd] Command: " + ocmd);
          let cmd = ocmd;
          if (!decaiYolo && !myYolo) {
            cmd = decaiAutoRepl(ocmd);
          }
          console.log("[r2cmd] Running: " + cmd);
          if (false) {
            r2.cmd("-e scr.color=0");
            res = r2.cmd(cmd).trim();
            r2.cmd("-e scr.color=2");
          } else {
            const obj = r2.cmd2(cmd);
            const logs = (obj.logs)
              ? obj.logs.map((x) => x.type + ": " + x.message).join("\n")
              : "";
            res = (obj.res + logs).trim();
            console.log(res);
            res = trimAnsi(res);
          }
          if (decaiDebug) {
            console.log("<r2output>");
            console.log(res);
            console.log("<(r2output>");
          }
          replies.push(
            JSON.stringify({
              action: "response",
              command: cmd,
              description: o.description,
              response: res,
            }),
          );
        } else if (o.action === "reply") {
          console.log("Done");
          console.log(o.response);
          break;
        } else {
          console.log("Unknown response");
          console.log(JSON.stringify(out));
        }
      } catch (e) {
        const response = out.indexOf('response": "');
        if (response !== -1) {
          const res = out.slice(response + 12).replace(/\\n/g, "\n").replace(
            /\\/g,
            "",
          );
          console.log(res);
        } else {
          console.log(out);
          console.error(e);
        }
        break;
      }
    }
  }
  function r2ai(queryText, fileData, hideprompt) {
    if (!fileData) {
      fileData = "";
    }
    fileData = fileData.replace(/\`/g, ""); // Don't replace single quotes with double quotes here
    queryText = queryText.replace(/'/g, "");
    if (decaiApi === "r2" || decaiApi === "r2ai") {
      const fileName = tmpdir(".pdc.txt");
      fileDump(fileName, fileData);
      const q = queryText.startsWith("-")
        ? queryText
        : ["-i", fileName, queryText].join(" ");
      const host = decaiBaseurl ? decaiBaseurl + "/cmd" : decaiHost + ":" + decaiPort + "/cmd";
      const ss = q.replace(/ /g, "%20").replace(/'/g, "\\'");
      const cmd = 'curl -s "' + host + "/" + ss +
        '" || echo "Cannot curl, use r2ai-server or r2ai -w"';
      debug.log(cmd);
      return r2.syscmds(cmd);
    }
    if (queryText.startsWith("-")) { // -i
      return "";
    }
    let q = queryText + ":\n" + fileData;
    if (maxInputTokens > 0 && q.length > maxInputTokens) {
      // making sure we do not send more that the limit
      q = q.slice(0, maxInputTokens);
    }
    if (decaiApi === "anthropic" || decaiApi === "claude") {
      return r2aiAnthropic(q, hideprompt);
    }
    if (decaiApi === "mistral") {
      return r2aiMistral(q, hideprompt);
    }
    if (decaiApi === "groq") {
      return r2aiGroq(q, hideprompt);
    }
    if (decaiApi === "deepseek") {
      return r2aiDeepseek(q, hideprompt);
    }
    if (decaiApi === "google" || decaiApi === "gemini") {
      return r2aiGemini(q, hideprompt);
    }
    if (decaiApi === "ollama") {
      return r2aiOllama(q, hideprompt);
    }
    if (decaiApi === "huggingface" || decaiApi === "hf") {
      return r2aiHuggingFace(q, hideprompt);
    }
    if (decaiApi === "openapi") {
      return r2aiOpenAPI(q, hideprompt);
    }
    if (decaiApi === "xai") {
      return r2aiXai(q, hideprompt);
    }
    if (decaiApi === "vllm") {
      return r2aiVLLM(q, hideprompt);
    }
    if (decaiApi === "openapi2") {
      return r2aiOpenAPI2(q, hideprompt);
    }
    if (decaiApi === "openai") {
      return r2aiOpenAI(q, hideprompt);
    }
    return "Unknown value for 'decai -e api'. Use r2ai, claude, ollama, hf, openapi, openapi2 or openai";
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
        case "a": // "-a" // auto mode
          decaiAuto(args.slice(2).trim());
          break;
        case "m": // "-m"
          var arg0 = args.slice(2).trim();
          if (arg0 === "=") {
            r2aidec("-e model=");
          } else if (arg0) {
            r2aidec("-e model=" + arg0);
          } else {
            r2aidec("-e model");
          }
          break;
        case "n": // "-n"
        case "f": // "-f"
          out = r2.cmd("axff~$$[3]");
          // out = r2.cmd("axffq~$$"); // requires r2-5.9.9
          var considerations = r2.cmd("fd.").trim().split(/\n/).filter((x) =>
            !x.startsWith("secti")
          ).join(",");
          // console.log(considerations);
          r2ai("-R");
          out = r2ai(
            "give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: " +
              considerations,
            out,
          ).trim();
          out += " @ " + r2.cmd("?v $FB").trim();
          break;
        case "v": // "-v"
          out = r2.cmd("afv;pdc");
          r2ai("-R");
          out = r2ai(
            "guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",
            out,
          );
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
            decaiPrompt = args;
          } else {
            console.log(decaiPrompt);
          }
          break;
        case "R": // "-R"
          decaiPrompt = defaultPrompt;
          break;
        case "s": // "-s"
          out = decaiSignature();
          break;
        case "V": // "-V"
          r2aidec(
            "-Q find vulnerabilities, dont show the code, only show the response, provide a sample exploit",
          );
          break;
        case "k": // "-k"
          listApiKeys();
          break;
        case "e": // "-e"
          args = args.slice(2).trim();
          if (args) {
            decaiEval(args);
          } else {
            for (const key of Object.keys(config)) {
              const v = config[key].get();
              console.log("decai -e " + key + "=" + v);
            }
          }
          break;
        case "q": // "-q"
          try {
            out = r2ai(args.slice(2).trim(), null, true);
          } catch (e) {
            console.error(e, e.stack);
          }
          break;
        case "Q": // "-Q"
          out = r2ai(args.slice(2).trim(), lastOutput);
          break;
        case "x": // "-x"
          out = decaiExplain();
          if (args[2] == "*" || args[2] == "r") { // "-xr"
            out = "'CC " + out;
          }
          break;
        case "d": // "-d"
          if (args[2] == "r") { // "dr"
            out = decaiDecompile(args.slice(2), true, decaiCache, true);
          } else if (args[2] == "d") { // "dd"
            out = decaiDecompile(args, false, false, false);
          } else if (args[2] == "D") { // "dD"
            out = decaiDecompile(args, true, false, false);
          } else {
            out = decaiDecompile(args, false, decaiCache, false);
          }
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
