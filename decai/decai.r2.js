📦
27619 /main.js
✄
var te="1.3.6",y="decai",A="~/.config/r2ai",K=A+"/apikeys.txt",O=A+"/decai.txt",U="Rewrite this pseudocode into concise and clean code. Output only the provided function. Do not add wrappers, helper examples, test code, or main-like functions. Replace goto with structured control flow, simplify as much as possible, infer types and use better names for variables and parameters, some strings may be appearing as comments, preserve only what is implied by the input, and remove dead code.",B={decai:`# Using Decai

Decai is the radare2 plugin for decompiling functions with the help of language models.

By default uses a local ollama server, but can you can pick any other service by using 'decai -e api=?'.

[0x00000000]> decai -e api=?
r2ai deepseek anthropic claude gemini groq hf lmstudio mistral ollama ollamacloud openapi opencode openai openrouter vllm xai zen

## Using Ollama

* Visit https://ollama.com to install it.
* Download the model of choice: 'ollama run llama3.3'
* Configure decai to use the given model with: 'decai -e model=?'

These are the most recommended models for decompiling in local:

* hhao/qwen2.5-coder-tools:latest (18GB of ram)
* hhao/qwen2.5-coder-tools:32b (24GB of ram required)

## Common Options
* 'decai -e baseurl=<url>' override default host and port for API endpoint (e.g., 'http://localhost:11434')
* 'decai -e headers=Authorization: Bearer ...\\nUser-Agent: curl/8.7.1' add or override HTTP headers
* "export DECAI_HEADERS='Authorization: Bearer ...\\nUser-Agent: curl/8.7.1'" set extra headers from the environment
* 'decai -e timeout=0' disable curl timeouts, or set a positive number of seconds

* 'decai -e deterministic=true' to remove randomness from decompilation responses
* 'decai -e lang=Python' to output the decompilation in Python instead of C
* 'decai -e hlang=Catalan' to add comments or explanations in that language (instead of English)
* 'decai -e cmds=pdd,pdg' use r2dec and r2ghidra instead of r2's pdc as input for decompiling
* 'decai -e prompt=..' default prompt must be fine for most models and binaries, feel free to tweak it

## API Keys

Remove services like OpenAI, Mistral, Anthropic, Grok, Gemini, .. require API keys to work.

See 'decai -k' to list the status of available APIkeys
Use 'decai -K' to edit apikeys.txt and 'decai -E' to edit decai.txt.

Decai will pick them from the environment or the config files in your home:

* echo KEY > ~/.r2ai.openai-key
* export OPENAI_API_KEY=...
* put one 'key=value' pair per line in ~/.config/r2ai/decai.txt

## Using the R2AI Server:

Install r2ai or r2ai-server with r2pm:

[0x0000000]> decai -e api=r2ai
[0x0000000]> r2pm -ci r2ai

Choose one of the recommended models (after r2pm -r r2ai):

* -m ibm-granite/granite-20b-code-instruct-8k-GGUF
* -m QuantFactory/granite-8b-code-instruct-4k-GGUF
* -m TheBloke/Mistral-7B-Instruct-v0.2-GGUF

Start the webserver:

$ r2pm -r r2ai-server -l r2ai -m granite-8...
`,auto:`# Radare2 Auto Mode

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

* On Swift binaries run...
`};var x={decopipe:{use:!1},host:"http://localhost",port:"11434",baseurl:"",extraHeaders:[],api:"ollama",pipeline:"",commands:"pdc",yolo:!1,tts:!1,language:"C",humanLanguage:"English",deterministic:!0,debug:!1,timeout:180,think:"",useFiles:!1,contextFile:"",model:"",cache:!1,maxInputTokens:-1,prompt:U,lastOutput:""},o={...x,decopipe:{...x.decopipe},extraHeaders:[...x.extraHeaders]};function ne(e){return(r2.cmd("-e dir.tmp").trim()??".")+"/"+e}function T(e,t){r2.cmd("'mkdir -p "+e),r2.cmd("'touch "+t)}function _(e){return(r2.cmd2("test -h").logs?.[0]?.message??"").includes("-fdx")?!0:r2.cmd("'test -vf "+e).startsWith("found")}function Y(e,t){return e+" ".repeat(Math.max(0,t-e.length))}function oe(e){return e.replace(/\x1b\[[0-9;]*m/g,"")}function re(e){let t=e.match(/```json\s*([\s\S]*?)```/);return t&&t[1]?t[1].trim():e}function ie(e){let t=e,n=t.indexOf("{");n!==-1&&(t=t.slice(n));let r=t.lastIndexOf("}");return r!==-1&&(t=t.slice(0,r+1)),t}function G(e){return btoa(e)}function ae(e,t){let n=G(t);r2.cmd("p6ds "+n+" > "+e)}function E(e){let t=e;return t=t.replace(/<think>[\s\S]*?<\/think>/gi,""),t.split(`
`).filter(n=>!n.trim().startsWith("```")).join(`
`)}function J(e){o.debug&&console.log(e)}function se(e){let t={};for(let n of e.split(/\r?\n/)){let r=n.trim();if(!r||r.startsWith("#"))continue;let[i,...a]=r.split("=");if(!i||a.length===0)continue;let l=a.join("=").trim(),s=i.toLowerCase().replace(/_api_key$/i,"");t[s]=l}return t}var Ce={mistral:"MISTRAL_API_KEY",anthropic:"ANTHROPIC_API_KEY",huggingface:"HUGGINGFACE_API_KEY",openai:"OPENAI_API_KEY",gemini:"GEMINI_API_KEY",deepseek:"DEEPSEEK_API_KEY",xai:"XAI_API_KEY",ollama:"OLLAMA_API_KEY",ollamacloud:"OLLAMA_API_KEY",opencode:"OPENCODE_API_KEY",zen:"OPENCODE_API_KEY",openrouter:"OPENROUTER_API_KEY",groq:"GROQ_API_KEY"};function q(e,t){let n=r2.cmd("'%"+t).trim();if(!n.includes("=")&&n!=="")return[n.trim(),null,"env"];let r=e.toLowerCase(),i=K;if(_(i)){let l=r2.cmd("'cat "+i),s=se(l);if(r in s)return[s[r],null,"txt"]}let a="~/.r2ai."+r+"-key";if(_(a)){let l=r2.cmd("'cat "+a);return l===""?[null,"Cannot read "+a,"no"]:[l.trim(),null,"file"]}return[null,"Not available","nope"]}function le(){T(A,K),r2.cmd("'ed "+K)}function $(){Object.entries(Ce).forEach(([e,t])=>{let n=q(e,t)[2];console.log(n,"	",e)})}var Re=["DECAI_HEADERS","R2AI_HEADERS"];function Me(e){let t=r2.cmd("'%"+e).trim();return t!==""&&!t.includes("=")?t:""}function ce(e){return e.trim().toLowerCase()}function ue(e){let t=e.indexOf(":"),n=e.indexOf("="),r=t!==-1&&(n===-1||t<n)?t:n;if(r===-1)return null;let i=e.slice(0,r).trim();return i===""?null:{name:i,value:e.slice(r+1).trim()}}function de(e){return e.value===""?`${e.name}:`:`${e.name}: ${e.value}`}function z(e){let t=new Map,n=e.replace(/\\n/g,`
`);for(let r of n.split(/\r?\n/g)){let i=r.trim();if(!i||i.startsWith("#"))continue;let a=ue(i);a&&t.set(ce(a.name),de(a))}return Array.from(t.values())}function pe(e){return e.join("\\n")}function P(...e){let t=new Map;for(let n of e)for(let r of n){let i=ue(r);i&&t.set(ce(i.name),de(i))}return Array.from(t.values())}function Ne(){for(let e of Re){let t=Me(e);if(t)return z(t)}return[]}function fe(){return P(Ne(),o.extraHeaders)}function I(e){return`'${e.replace(/'/g,`'"'"'`)}'`}function Ke(e){let{method:t,url:n,headers:r,payload:i}=e,a=["curl","-s"];if(o.timeout>0&&a.push("--max-time",String(o.timeout)),P(["Content-Type: application/json"],r).forEach(s=>a.push("-H",I(s))),t==="POST"){if(!i)throw new Error("Payload required for POST requests");let s=r2.fdump(i);a.push("--data-binary","@"+I(s),I(n));let c=a.join(" ")+"; rm "+I(s);return J(c),r2.syscmds(c)}else{a.push(I(n));let s=a.join(" ");return J(s),r2.syscmds(s)}}function Ue(e){let t=e.split(`
`).filter(i=>i.trim()!=="");if(t.length<=1)return null;let n="",r=null;for(let i of t)try{let a=JSON.parse(i);if(a.error)return a;a.message?.content!==void 0&&(n+=a.message.content),r=a}catch{return null}return r?(r.message={role:"assistant",content:n},r):null}function me(e){try{let t=Ke(e).trim();if(t==="")return{error:"empty response"};try{return JSON.parse(t)}catch{let n=Ue(t);return n||{error:t,rawOutput:t}}}catch(t){return{error:t.message}}}function v(e,t){return me({method:"GET",url:e,headers:t})}function he(e,t,n){return me({method:"POST",url:e,headers:t,payload:n})}function V(e){return e.split("_")[0].toLowerCase()}function S(e){if(!e.authKey)return;let t=Array.from(new Set([e.keyName,V(e.authKey)].filter(Boolean))),n;for(let r of t){let i=q(r,e.authKey);if(i[0])return i;!n&&i[2]!=="nope"&&(n=i)}return n||q(V(e.authKey),e.authKey)}function ge(e){if(e)return typeof e=="string"?e:e.message}function C(e){return o.baseurl||e.defaultBaseUrl}function R(e,t=fe()){return P(e,t)}function Te(e){return e?["Authorization: Bearer "+e]:[]}function qe(e){let t=["anthropic-version: 2023-06-01"];return e?P(t,["x-api-key: "+e]):t}function M(e,t){switch(e.authStyle||"none"){case"bearer":return Te(t);case"anthropic":return qe(t);case"none":default:return[]}}function ye(e,t,n){let r=v(e,t),i=ge(r.error);return i?(console.error(i),"error invalid response"):r.data?.map(n).join(`
`)||""}function De(e,t){let n=new Set;return e.filter(r=>{let i=t(r);return n.has(i)?!1:(n.add(i),!0)})}function He(e){let t=S(e),n=C(e),r=R(M(e,t?.[0]||null));return ye(n+"/v1/models",r,i=>i.id)}function Le(e){let t=S(e),n=C(e),r=R(M(e,t?.[0]||null));return ye(n+"/v1/models",r,i=>i.id)}function je(e){let t=v(C(e)+"/api/tags",R(M(e,S(e)?.[0]||null))),n=ge(t.error);return n?(console.error(n),"error invalid response"):t.models?.map(r=>r.name).join(`
`)||""}function Fe(e){let t=S(e),n=v(C(e)+"/v1/models",R(M(e,t?.[0]||null)));return n.data?De(n.data,r=>r.name||r.id).map(r=>[Y(r.name||r.id,30),Y(""+(r.max_context_length||""),10),r.description||""].join(" ")).join(`
`):""}var Be={openai:{buildPayload:(e,t)=>({stream:!1,model:e,messages:[{role:"user",content:t}]}),parseResponse:e=>{if(e.error){let t=typeof e.error=="object"?e.error.message:e.error;throw new Error(t||"Unknown error")}if(e.choices&&e.choices[0]?.message?.content)return E(e.choices[0].message.content);throw new Error("Invalid response format")},buildUrl:e=>e+"/v1/chat/completions"},anthropic:{buildPayload:(e,t)=>{let n={model:e,max_tokens:5128,messages:[{role:"user",content:t}]};return W()&&(n.thinking={type:"enabled",budget_tokens:4096},n.max_tokens=16e3),o.deterministic&&!W()&&Object.assign(n,{temperature:0,top_p:0,top_k:1}),n},parseResponse:e=>{if(e.content&&Array.isArray(e.content)){let t=[];for(let n of e.content)n.text&&t.push(n.text);if(t.length>0)return E(t.join(`
`))}if(e.error){let t=typeof e.error=="object"?e.error.message:e.error;throw new Error(t||"Unknown error")}throw new Error("Invalid response format")},buildUrl:e=>e+"/v1/messages"},ollama:{buildPayload:(e,t)=>{let n={stream:!1,model:e,messages:[{role:"user",content:t}]};return W()?o.think==="true"||o.think==="1"?n.think=!0:n.think=o.think:n.think=!1,o.deterministic&&(n.options={repeat_last_n:0,top_p:1,top_k:1,temperature:0,repeat_penalty:1,seed:123}),n},parseResponse:e=>{if(e.error){let t=typeof e.error=="string"?e.error:JSON.stringify(e.error);throw new Error(t)}if(e.message?.content)return E(e.message.content);throw new Error(JSON.stringify(e))},buildUrl:e=>e+"/api/chat"},gemini:{buildPayload:(e,t)=>{let n={contents:[{parts:[{text:t}]}]},r={};return o.deterministic&&Object.assign(r,{temperature:0,topP:1,topK:1}),o.think!==""&&(X()?r.thinkingConfig={thinkingBudget:0}:r.thinkingConfig={thinkingBudget:8192}),Object.keys(r).length>0&&(n.generationConfig=r),n},parseResponse:e=>{if(e.candidates&&e.candidates[0]?.content?.parts){let n=e.candidates[0].content.parts.filter(r=>!r.thought&&r.text).map(r=>r.text);if(n.length>0)return E(n.join(`
`))}throw e.error?new Error(typeof e.error=="string"?e.error:JSON.stringify(e.error)):(console.log(JSON.stringify(e)),new Error("Invalid response format"))},buildUrl:(e,t,n)=>`${e}/v1beta/models/${t}:generateContent?key=${n}`,requiresUrlApiKey:!0}},be={anthropic:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseUrl:"https://api.anthropic.com",authKey:"ANTHROPIC_API_KEY",keyName:"anthropic",authStyle:"anthropic",apiStyle:"anthropic"},claude:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseUrl:"https://api.anthropic.com",authKey:"ANTHROPIC_API_KEY",keyName:"claude",authStyle:"anthropic",apiStyle:"anthropic"},openai:{defaultModel:"gpt-4o-mini",defaultBaseUrl:"https://api.openai.com",authKey:"OPENAI_API_KEY",authStyle:"bearer",apiStyle:"openai"},ollama:{defaultModel:"qwen2.5-coder:latest",defaultBaseUrl:"http://localhost:11434",authStyle:"none",apiStyle:"ollama"},ollamacloud:{defaultModel:"gpt-oss:120b",defaultBaseUrl:"https://ollama.com",authKey:"OLLAMA_API_KEY",keyName:"ollamacloud",authStyle:"bearer",apiStyle:"ollama"},opencode:{defaultModel:"big-pickle",defaultBaseUrl:"https://opencode.ai/zen",authKey:"OPENCODE_API_KEY",keyName:"opencode",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["big-pickle","glm-5","kimi-k2.5"]},zen:{defaultModel:"big-pickle",defaultBaseUrl:"https://opencode.ai/zen",authKey:"OPENCODE_API_KEY",keyName:"zen",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["big-pickle","glm-5","kimi-k2.5"]},gemini:{defaultModel:"gemini-2.5-flash",defaultBaseUrl:"https://generativelanguage.googleapis.com",authKey:"GEMINI_API_KEY",authStyle:"none",apiStyle:"gemini",hardcodedModels:["gemini-2.0-flash","gemini-2.0-flash-lite","gemini-2.5-pro","gemini-2.5-flash","gemini-2.5-flash-lite"]},mistral:{defaultModel:"codestral-latest",defaultBaseUrl:"https://api.mistral.ai",authKey:"MISTRAL_API_KEY",authStyle:"bearer",apiStyle:"openai"},xai:{defaultModel:"grok-beta",defaultBaseUrl:"https://api.x.ai",authKey:"XAI_API_KEY",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["grok-2","grok-beta"]},lmstudio:{defaultModel:"local-model",defaultBaseUrl:"http://127.0.0.1:1234",authStyle:"none",apiStyle:"openai"},deepseek:{defaultModel:"deepseek-coder",defaultBaseUrl:"https://api.deepseek.com",authKey:"DEEPSEEK_API_KEY",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["deepseek-coder","deepseek-chat"]},openrouter:{defaultModel:"openai/gpt-4o-mini",defaultBaseUrl:"https://openrouter.ai/api",authKey:"OPENROUTER_API_KEY",authStyle:"bearer",apiStyle:"openai"},groq:{defaultModel:"llama-3.3-70b-versatile",defaultBaseUrl:"https://api.groq.com/openai",authKey:"GROQ_API_KEY",authStyle:"bearer",apiStyle:"openai"}};function D(e){return be[e]}function Q(){return Object.keys(be)}function ke(e){let t=D(e);if(!t)throw new Error(`Unknown provider: ${e}`);if(e==="mistral")return Fe(t);switch(t.apiStyle){case"openai":return He(t);case"anthropic":return Le(t);case"ollama":return je(t);case"gemini":return"";default:return""}}function X(){return o.think==="false"||o.think==="0"}function W(){return o.think!==""&&!X()}function Ye(e,t,n){let r=e;return o.think!==""&&n==="openai"&&(X()?(r+=' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".',r+=" /no_think"):r="Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer."+r),t?r:o.prompt+Ge()+r}function Ge(){return`
.Translate the code into `+o.language+` programming language
`}function Je(e,t,n,r){let i=o.model||e.defaultModel,a=Ye(n,r,e.apiStyle),l=S(e);if(t.requiresUrlApiKey&&l?.[1]&&e.authKey)return`Cannot read ~/.r2ai.${V(e.authKey)}-key`;let s=t.buildPayload(i,a),c=M(e,l?.[0]||null);e.apiStyle==="ollama"&&c.push("Accept: application/x-ndjson");let p=R(c),d=t.buildUrl(C(e),i,l?.[0]||void 0);try{return t.parseResponse(he(d,p,JSON.stringify(s)))}catch(u){return"ERROR: "+u.message}}function xe(e,t){let n=D(o.api);return n?Je(n,Be[n.apiStyle],e,t):`Unknown value for 'decai -e api'. Available: ${Q().join(", ")}`}function Ee(e){let t=D(e);if(!t){console.error(`Unknown provider: ${e}`);return}try{let n=ke(e);n&&console.log(n),t.hardcodedModels&&t.hardcodedModels.forEach(r=>console.log(r)),e==="mistral"&&console.log("ministral-8b-latest"),!n&&!t.hardcodedModels&&console.log(t.defaultModel)}catch(n){let r=n;console.error(`Error listing models for ${e}:`,r.message),console.log(t.defaultModel)}}var Z=!1;function w(e){return e==="true"||e==="1"}var Ae={pipeline:{get:()=>o.pipeline,set:e=>{o.pipeline=e;try{o.decopipe=JSON.parse(r2.cmd("cat "+e))}catch(t){console.error(t)}}},model:{get:()=>o.model,set:e=>{e==="?"?Ee(o.api):o.model=e.trim()}},deterministic:{get:()=>o.deterministic,set:e=>{o.deterministic=w(e)}},files:{get:()=>o.useFiles,set:e=>{o.useFiles=w(e)}},think:{get:()=>o.think||"false",set:e=>{o.think=e}},debug:{get:()=>o.debug,set:e=>{o.debug=w(e)}},timeout:{get:()=>o.timeout,set:e=>{o.timeout=Math.max(0,parseInt(e,10)||0)}},api:{get:()=>o.api,set:e=>{if(e==="?"){let t=Q().join(`
`);console.error(t)}else o.api=e}},lang:{get:()=>o.language,set:e=>{o.language=e}},hlang:{get:()=>o.humanLanguage,set:e=>{o.humanLanguage=e}},cache:{get:()=>o.cache,set:e=>{o.cache=w(e)}},cmds:{get:()=>o.commands,set:e=>{o.commands=e}},tts:{get:()=>o.tts,set:e=>{o.tts=w(e)}},yolo:{get:()=>o.yolo,set:e=>{o.yolo=w(e)}},prompt:{get:()=>o.prompt,set:e=>{o.prompt=e}},ctxfile:{get:()=>o.contextFile,set:e=>{o.contextFile=e}},baseurl:{get:()=>o.baseurl,set:e=>{o.baseurl=e}},headers:{get:()=>pe(o.extraHeaders),set:e=>{o.extraHeaders=z(e)}},maxtokens:{get:()=>o.maxInputTokens,set:e=>{o.maxInputTokens=parseInt(e,10)||-1}}};function $e(){let e={host:o.host,port:o.port,lastOutput:o.lastOutput};Object.assign(o,x,e),o.decopipe={...x.decopipe},o.extraHeaders=[...x.extraHeaders]}function ze(e){let t=e.trim();return!t||t.startsWith("#")?null:t.startsWith("decai -e ")?t.slice(9).trim():t}function b(e){let t=e.indexOf("="),n=t===-1?e:e.slice(0,t),r=t===-1?void 0:e.slice(t+1),i=Ae[n];if(!i){console.error("Unknown config key");return}typeof r<"u"?i.set(r):console.log(i.get())}function Pe(){Object.entries(Ae).forEach(([e,t])=>{let n=t.get();console.log("decai -e "+e+"="+n)})}function ve(){if($e(),!_(O))return;let e=r2.call("cat "+O);for(let t of e.split(/\r?\n/)){let n=ze(t);n&&n[0]!="#"&&b(n)}}function we(){Z||(ve(),Z=!0)}function Oe(){T(A,O),r2.cmd("'ed "+O),ve(),Z=!0}function f(e,t,n=!1){let r=(t||"").replace(/`/g,""),i=e.replace(/'/g,"");if(o.api==="r2"||o.api==="r2ai"){let l=ne(".pdc.txt");ae(l,r);let s=i.startsWith("-")?i:["-i",l,i].join(" "),p=(o.baseurl?o.baseurl+"/cmd":o.host+":"+o.port+"/cmd")+"/"+encodeURIComponent(s),d=v(p,[]);return d.error?`Error: ${d.error}`:d.result||JSON.stringify(d)||"Cannot curl, use r2ai-server or r2ai -w"}if(i.startsWith("-"))return"";let a=i+`:
`+r;return o.maxInputTokens>0&&a.length>o.maxInputTokens&&(a=a.slice(0,o.maxInputTokens)),xe(a,n)}function _e(){let e="",t=n=>e+=" "+y+" "+n+`
`;e+="Usage: "+y+` (-h) ...
`,e+="Version: "+te+`
`,t("-a [query]    - solve query with auto mode"),t("-b [url]      - set base URL (alias for decai -e baseurl)"),t("-d [f1 ..]    - decompile given functions"),t("-dd [..]      - same as above, but ignoring cache"),t("-dD [query]   - decompile current function with given extra query"),t("-dr           - decompile function and its called ones (recursive)"),t("-e            - display and change eval config vars"),t("-E            - edit and run decai.txt"),t("-h            - show this help"),t("-H            - help setting up r2ai"),t("-i [f] [q]    - include given file and query"),t("-k            - list API key status"),t("-K            - edit apikeys.txt"),t("-m [model]    - use -m? or -e model=? to list the available models"),t("-n            - suggest better function name"),t("-p [provider] - same as decai -e api (will be provider)"),t("-q [text]     - query language model with given text"),t("-Q [text]     - query on top of the last output"),t("-r [prompt]   - change role prompt (same as: decai -e prompt)"),t("-R            - reset role prompt to default prompt"),t("-s            - function signature"),t("-v            - show local variables"),t("-V            - find vulnerabilities"),t("-x[*]         - eXplain current function (-x* for r2 script)"),r2.log(e.trim())}function H(e,t,n,r){if(n){let s=r2.cmd("anos").trim();if(s.length>0)return s}let i="";if(r){let s=r2.cmd("s");i+=`## Context functions:
`;let c=r2.cmdAt("axff~^C[2]~$$",s);for(let p of c.split(/\n/g))i+=r2.cmd("pdc@"+p);r2.cmd("s "+s)}let a=t?" "+e:"",l=r2.cmd("e scr.color");try{let s=e.slice(2).trim(),c=0,p="";o.contextFile!==""&&r2.cmd2("test -f "+o.contextFile).value===0&&(p+=`## Context:
[START]
`+r2.cmd("cat "+o.contextFile)+`
[END]
`),r2.cmd("e scr.color=0");let d=`## Before:
`;for(let m of o.commands.split(",")){if(m.trim()==="")continue;let N=t||s.trim().length===0?m:m+"@@= "+s,k=r2.cmd(N);k.length>5&&(d+="Output of "+m+`:
[START]
`+k+`
[END]
`,c++)}if(d+=`## After:
`,r2.cmd("e scr.color="+l),c===0){console.error("Nothing to do.");return}let u="";if(o.decopipe.use){let m=o.model;try{let N=o.decopipe[o.decopipe.default],k=p+d;for(let F of N.pipeline){F.model&&(o.model=F.model);let ee=F.query+". "+N.globalQuery;u=f(ee,k,!0),o.debug&&console.log(`QUERY
`,ee,`
INPUT
`,k,`
OUTPUT
`,u),k=u}u=k}finally{o.model=m}}else{let m=a;p+=d+i,u=f(m,p,!1),o.lastOutput=u}return n&&u.length>1&&r2.call("ano=base64:"+G(u)),u.startsWith("```")&&(u=u.replace(/```.*\n/,"").replace(/```$/,"")),u.trim()}catch(s){r2.cmd("e scr.color="+l);let c=s;console.error(c,c.stack);return}}function We(){let e=r2.cmd("e scr.color");r2.cmd("e scr.color=0");let t="[START]"+o.commands.split(",").map(i=>r2.cmd(i)).join(`
`)+"[END]";r2.cmd("e scr.color="+e);let r=f("Analyze function calls, references, comments and strings, loops and ignore registers and memory accesses. Explain the purpose of this function in a single short sentence. /no_think Do not introduce or argue the response, translation of the explanation in "+o.humanLanguage,t,!0).trim().split(/\n/g);return r[r.length-1].trim()}function Ve(){let e=o.language,t=r2.cmd("afv;pdc");o.language="C";let n="'afs "+f("analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the return. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",t,!1),r=n.indexOf("{");return r!==-1&&(n=n.substring(0,r)),o.language=e,n}function Qe(e,t){let n=[];for(;;){let r=B.auto;if(n.length>0){r+=`## Command Results

`;for(let a of n){let l=JSON.parse(a);r+="### "+l.command+"\n\n```\n"+l.response+"\n```\n"}}r+=`

## User Prompt

`+e,o.debug&&console.log(`#### input
`,r,`
#### /input`),console.log("Thinking...");let i=f("",r,!0);o.debug&&console.log(`#### output
`,i,`
#### /output`);try{let a=JSON.parse(ie(re(E(i))));if(a.action==="r2cmd"||a.action==="response"||a.action===a.command){let l=a.command||"";a.reason&&(console.log("[r2cmd] Reasoning: "+a.reason),o.tts&&(r2.syscmd("pkill say"),r2.syscmd("say -v Alex -r 250 '"+a.reason.replace(/'/g,"")+"' &"))),console.log("[r2cmd] Action: "+a.description),console.log("[r2cmd] Command: "+l);let s=l;o.yolo||(s=Xe(l,t)),console.log("[r2cmd] Running: "+s);let c=r2.cmd2(s),p=c.logs?c.logs.map(m=>m.type+": "+m.message).join(`
`):"",d=(c.res+p).trim();console.log(d);let u=oe(d);o.debug&&console.log(`<r2output>
`,u,`
<(r2output>`),n.push(JSON.stringify({action:"response",command:s,description:a.description,response:u}))}else if(a.action==="reply"){console.log(`Done
`,a.response);break}else{console.log(`Unknown response
`,JSON.stringify(i));break}}catch(a){let l=i.indexOf('response": "');if(l!==-1){let s=i.slice(l+12).replace(/\\n/g,`
`).replace(/\\/g,"");console.log(s)}else console.log(i),console.error(a);break}}}function Xe(e,t){for(;;){let n=r2.cmd("'?ie Tweak command? ('?' for help)").trim();if(n==="q!"){console.error("Break!");break}if(n==="?"){Ze();continue}else if(n.startsWith(":")){console.log(r2.cmd(n.slice(1)));continue}else if(n.startsWith("-e")){t(n);continue}else{if(n==="!")return"?e do NOT execute '"+e+"' again, continue without it";if(n.startsWith("!")){console.log(r2.syscmd(n.slice(1)));continue}else{if(n==="q")return"?e All data collected!. Do not call more commands, reply the solutions";if(n){let r=n.indexOf("#");return r!==-1?n.slice(0,r).trim():n}else return e}}}return e}function Ze(){console.log(" '!'     do not run this command"),console.log(" '!c'    run system command"),console.log(" 'q'     to quit auto and try to solve"),console.log(" 'q!'    quit auto without solving"),console.log(" 'c # C' use given command with comment"),console.log(" ':c'    run r2 command without feeding auto"),console.log(" '-e'    set decai configuration variables")}function et(e){return e.slice(2).trim()}function L(){return r2.cmd("afi.").trim().length>0}var j="Cannot find function at current offset";function Ie(e,t){if(e===""||!e.startsWith("-")){_e();return}let n="",r=e[1],i=et(e);switch(r){case"H":console.log(B.decai);break;case"a":Qe(i,t);break;case"m":{i==="="?b("model="):i?b("model="+i):b("model");break}case"n":case"f":{if(!L()){n=j;break}n=r2.cmd("axff~$[3]");let a=r2.cmd("fd.").trim().split(/\n/).filter(l=>!l.startsWith("secti")).join(",");n=f("give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: "+a,n,!1).trim(),n+=" @ "+r2.cmd("?v $FB").trim();break}case"v":{if(!L()){n=j;break}n=r2.cmd("afv;pdc"),n=f("guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",n,!1);break}case"i":{let a=i.split(/\s+/).filter(Boolean);if(a.length>=2){let l=a[0],s=a.slice(1).join(" "),c=r2.cmd("cat "+l);console.log(f(s,c,!0))}else console.log("Use: decai -i [file] [query ...]");break}case"p":{i?b("api="+i):$();break}case"r":{i?o.prompt=i:console.log(o.prompt);break}case"R":o.prompt=U;break;case"s":if(!L()){n=j;break}n=Ve();break;case"V":n=f("find vulnerabilities, dont show the code, only show the response, provide a sample exploit",o.lastOutput,!1);break;case"K":le();break;case"E":Oe();break;case"k":$();break;case"b":{i?b("baseurl="+i):console.log(o.baseurl);break}case"e":{i?b(i):Pe();break}case"q":try{n=f(i,null,!0)}catch(a){let l=a;console.error(l,l.stack)}break;case"Q":n=f(i,o.lastOutput,!1);break;case"x":if(!L()){n=j;break}n=We(),(e[2]==="*"||e[2]==="r")&&(n="'CC "+n);break;case"d":e[2]==="r"?n=H(e.slice(2),!0,o.cache,!0)||"":e[2]==="d"?n=H(e,!1,!1,!1)||"":e[2]==="D"?n=H(e,!0,!1,!1)||"":n=H(e,!1,o.cache,!1)||"";break;default:_e();break}return n||void 0}function Se(e){we();let t=Ie(e,Se);return t&&r2.log(t),!0}function tt(){r2.unload("core",y),r2.plugin("core",function(){function e(t){if(t.startsWith(y)){let n=t.slice(y.length).trim();return Se(n)}return!1}return{name:y,license:"MIT",desc:"r2 decompiler based on r2ai",call:e}})}tt();
