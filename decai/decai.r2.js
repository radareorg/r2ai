📦
26677 /main.js
✄
var ee="1.3.8",y="decai",w="~/.config/r2ai",M=w+"/apikeys.txt",I=w+"/decai.txt",N="Rewrite this pseudocode into concise and clean code. Output only the provided function. Do not add wrappers, helper examples, test code, or main-like functions. Replace goto with structured control flow, simplify as much as possible, infer types and use better names for variables and parameters, some strings may be appearing as comments, preserve only what is implied by the input, and remove dead code.",F={decai:`# Using Decai

Decai is the radare2 plugin for decompiling functions with the help of language models.

By default uses a local ollama server, but can you can pick any other service by using 'decai -e api=?'.

[0x00000000]> decai -e api=?
r2ai deepseek anthropic claude gemini groq hf lmstudio mistral ollama ollamacloud openapi openai openrouter vllm xai zen

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
`};var x={decopipe:{use:!1},host:"http://localhost",port:"11434",baseurl:"",extraHeaders:[],api:"ollama",pipeline:"",commands:"pdc",yolo:!1,tts:!1,language:"C",humanLanguage:"English",deterministic:!0,debug:!1,timeout:180,think:"",useFiles:!1,contextFile:"",model:"",cache:!1,maxInputTokens:-1,prompt:N,lastOutput:""},r={...x,decopipe:{...x.decopipe},extraHeaders:[...x.extraHeaders]};function te(e){return(r2.cmd("-e dir.tmp").trim()??".")+"/"+e}function q(e,t){r2.cmd("'mkdir -p "+e),r2.cmd("'touch "+t)}function _(e){return(r2.cmd2("test -h").logs?.[0]?.message??"").includes("-fdx")?!0:r2.cmd("'test -vf "+e).startsWith("found")}function L(e,t){return e+" ".repeat(Math.max(0,t-e.length))}function ne(e){return e.replace(/\x1b\[[0-9;]*m/g,"")}function oe(e){let t=e.match(/```json\s*([\s\S]*?)```/);return t&&t[1]?t[1].trim():e}function re(e){let t=e,n=t.indexOf("{");n!==-1&&(t=t.slice(n));let o=t.lastIndexOf("}");return o!==-1&&(t=t.slice(0,o+1)),t}function G(e){return btoa(e)}function ie(e,t){let n=G(t);r2.cmd("p6ds "+n+" > "+e)}function v(e){let t=e;return t=t.replace(/<think>[\s\S]*?<\/think>/gi,""),t.split(`
`).filter(n=>!n.trim().startsWith("```")).join(`
`)}function $(e){r.debug&&console.log(e)}function ae(e){let t={};for(let n of e.split(/\r?\n/)){let o=n.trim();if(!o||o.startsWith("#"))continue;let[i,...a]=o.split("=");if(!i||a.length===0)continue;let s=a.join("=").trim(),l=i.toLowerCase().replace(/_api_key$/i,"");t[l]=s}return t}var Re=["DECAI_HEADERS","R2AI_HEADERS"];function Ie(e){let t=r2.cmd("'%"+e).trim();return t!==""&&!t.includes("=")?t:""}function _e(e){return e.trim().toLowerCase()}function Ue(e){let t=e.indexOf(":"),n=e.indexOf("="),o=t!==-1&&(n===-1||t<n)?t:n;if(o===-1)return null;let i=e.slice(0,o).trim();return i===""?null:{name:i,value:e.slice(o+1).trim()}}function Me(e){return e.value===""?`${e.name}:`:`${e.name}: ${e.value}`}function se(e,t){for(let n of e){let o=Ue(n.trim());o&&t.set(_e(o.name),Me(o))}}function J(e){let t=new Map,n=e.replace(/\\n/g,`
`).split(/\r?\n/g).filter(o=>{let i=o.trim();return i&&!i.startsWith("#")});return se(n,t),Array.from(t.values())}function le(e){return e.join("\\n")}function E(...e){let t=new Map;for(let n of e)se(n,t);return Array.from(t.values())}function Ne(){for(let e of Re){let t=Ie(e);if(t)return J(t)}return[]}function ce(){return E(Ne(),r.extraHeaders)}function U(e){return`'${e.replace(/'/g,`'"'"'`)}'`}function qe(e){let{method:t,url:n,headers:o,payload:i}=e,a=["curl","-s"];if(r.timeout>0&&a.push("--max-time",String(r.timeout)),E(["Content-Type: application/json"],o).forEach(l=>a.push("-H",U(l))),t==="POST"){if(!i)throw new Error("Payload required for POST requests");let l=r2.fdump(i);a.push("--data-binary","@"+U(l),U(n));let u=a.join(" ")+"; rm "+U(l);return $(u),r2.syscmds(u)}else{a.push(U(n));let l=a.join(" ");return $(l),r2.syscmds(l)}}function Ke(e){let t=e.split(`
`).filter(i=>i.trim()!=="");if(t.length<=1)return null;let n="",o=null;for(let i of t)try{let a=JSON.parse(i);if(a.error)return a;a.message?.content!==void 0&&(n+=a.message.content),o=a}catch{return null}return o?(o.message={role:"assistant",content:n},o):null}function ue(e){try{let t=qe(e).trim();if(t==="")return{error:"empty response"};try{return JSON.parse(t)}catch{let n=Ke(t);return n||{error:t,rawOutput:t}}}catch(t){return{error:t.message}}}function A(e,t){return ue({method:"GET",url:e,headers:t})}function de(e,t,n){return ue({method:"POST",url:e,headers:t,payload:n})}function W(e){return e.split("_")[0].toLowerCase()}function fe(e){if(!e.authKey)return;let t=Array.from(new Set([e.keyName,W(e.authKey)].filter(Boolean))),n;for(let o of t){let i=K(o,e.authKey);if(i[0])return i;!n&&i[2]!=="nope"&&(n=i)}return n||K(W(e.authKey),e.authKey)}function O(e){if(e)return typeof e=="string"?e:e.message||JSON.stringify(e)}function pe(e){return r.baseurl||e.defaultBaseUrl}function me(e,t=ce()){return E(e,t)}function Te(e){return e?["Authorization: Bearer "+e]:[]}function He(e){let t=["anthropic-version: 2023-06-01"];return e?E(t,["x-api-key: "+e]):t}function he(e,t){switch(e.authStyle||"none"){case"bearer":return Te(t);case"anthropic":return He(t);case"none":default:return[]}}function De(e,t,n){let o=A(e,t),i=O(o.error);return i?(console.error(i),"error invalid response"):o.data?.map(n).join(`
`)||""}function je(e,t){let n=new Set;return e.filter(o=>{let i=t(o);return n.has(i)?!1:(n.add(i),!0)})}function z(e){let t=fe(e)?.[0]||null;return{baseUrl:pe(e),headers:me(he(e,t))}}function Be(e){let{baseUrl:t,headers:n}=z(e);return De(t+"/v1/models",n,o=>o.id)}function Fe(e){let{baseUrl:t,headers:n}=z(e),o=A(t+"/api/tags",n),i=O(o.error);return i?(console.error(i),"error invalid response"):o.models?.map(a=>a.name).join(`
`)||""}function Le(e){let{baseUrl:t,headers:n}=z(e),o=A(t+"/v1/models",n);return o.data?je(o.data,i=>i.name||i.id).map(i=>[L(i.name||i.id,30),L(""+(i.max_context_length||""),10),i.description||""].join(" ")).join(`
`):""}var Ge={openai:{buildPayload:(e,t)=>({stream:!1,model:e,messages:[{role:"user",content:t}]}),parseResponse:e=>{if(e.error)throw new Error(O(e.error)||"Unknown error");if(e.choices&&e.choices[0]?.message?.content)return v(e.choices[0].message.content);throw new Error("Invalid response format")},buildUrl:e=>e+"/v1/chat/completions"},anthropic:{buildPayload:(e,t)=>{let n={model:e,max_tokens:5128,messages:[{role:"user",content:t}]};return Y()&&(n.thinking={type:"enabled",budget_tokens:4096},n.max_tokens=16e3),r.deterministic&&!Y()&&Object.assign(n,{temperature:0,top_p:0,top_k:1}),n},parseResponse:e=>{if(e.content&&Array.isArray(e.content)){let t=[];for(let n of e.content)n.text&&t.push(n.text);if(t.length>0)return v(t.join(`
`))}throw e.error?new Error(O(e.error)||"Unknown error"):new Error("Invalid response format")},buildUrl:e=>e+"/v1/messages"},ollama:{buildPayload:(e,t)=>{let n={stream:!1,model:e,messages:[{role:"user",content:t}]};return Y()?r.think==="true"||r.think==="1"?n.think=!0:n.think=r.think:n.think=!1,r.deterministic&&(n.options={repeat_last_n:0,top_p:1,top_k:1,temperature:0,repeat_penalty:1,seed:123}),n},parseResponse:e=>{if(e.error)throw new Error(O(e.error));if(e.message?.content)return v(e.message.content);throw new Error(JSON.stringify(e))},buildUrl:e=>e+"/api/chat"},gemini:{buildPayload:(e,t)=>{let n={contents:[{parts:[{text:t}]}]},o={};return r.deterministic&&Object.assign(o,{temperature:0,topP:1,topK:1}),r.think!==""&&(Q()?o.thinkingConfig={thinkingBudget:0}:o.thinkingConfig={thinkingBudget:8192}),Object.keys(o).length>0&&(n.generationConfig=o),n},parseResponse:e=>{if(e.candidates&&e.candidates[0]?.content?.parts){let n=e.candidates[0].content.parts.filter(o=>!o.thought&&o.text).map(o=>o.text);if(n.length>0)return v(n.join(`
`))}throw e.error?new Error(O(e.error)):(console.log(JSON.stringify(e)),new Error("Invalid response format"))},buildUrl:(e,t,n)=>`${e}/v1beta/models/${t}:generateContent?key=${n}`,requiresUrlApiKey:!0}},T={anthropic:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseUrl:"https://api.anthropic.com",authKey:"ANTHROPIC_API_KEY",keyName:"anthropic",authStyle:"anthropic",apiStyle:"anthropic"},claude:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseUrl:"https://api.anthropic.com",authKey:"ANTHROPIC_API_KEY",keyName:"claude",authStyle:"anthropic",apiStyle:"anthropic"},openai:{defaultModel:"gpt-4o-mini",defaultBaseUrl:"https://api.openai.com",authKey:"OPENAI_API_KEY",authStyle:"bearer",apiStyle:"openai"},ollama:{defaultModel:"qwen2.5-coder:latest",defaultBaseUrl:"http://localhost:11434",authStyle:"none",apiStyle:"ollama"},ollamacloud:{defaultModel:"gpt-oss:120b",defaultBaseUrl:"https://ollama.com",authKey:"OLLAMA_API_KEY",keyName:"ollamacloud",authStyle:"bearer",apiStyle:"ollama"},zen:{defaultModel:"big-pickle",defaultBaseUrl:"https://opencode.ai/zen",authKey:"OPENCODE_API_KEY",keyName:"zen",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["big-pickle","glm-5","kimi-k2.5"]},gemini:{defaultModel:"gemini-2.5-flash",defaultBaseUrl:"https://generativelanguage.googleapis.com",authKey:"GEMINI_API_KEY",authStyle:"none",apiStyle:"gemini",hardcodedModels:["gemini-2.0-flash","gemini-2.0-flash-lite","gemini-2.5-pro","gemini-2.5-flash","gemini-2.5-flash-lite"]},mistral:{defaultModel:"codestral-latest",defaultBaseUrl:"https://api.mistral.ai",authKey:"MISTRAL_API_KEY",authStyle:"bearer",apiStyle:"openai"},xai:{defaultModel:"grok-beta",defaultBaseUrl:"https://api.x.ai",authKey:"XAI_API_KEY",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["grok-2","grok-beta"]},lmstudio:{defaultModel:"local-model",defaultBaseUrl:"http://127.0.0.1:1234",authStyle:"none",apiStyle:"openai"},deepseek:{defaultModel:"deepseek-coder",defaultBaseUrl:"https://api.deepseek.com",authKey:"DEEPSEEK_API_KEY",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["deepseek-coder","deepseek-chat"]},openrouter:{defaultModel:"openai/gpt-4o-mini",defaultBaseUrl:"https://openrouter.ai/api",authKey:"OPENROUTER_API_KEY",authStyle:"bearer",apiStyle:"openai"},groq:{defaultModel:"llama-3.3-70b-versatile",defaultBaseUrl:"https://api.groq.com/openai",authKey:"GROQ_API_KEY",authStyle:"bearer",apiStyle:"openai"}};function H(e){return T[e]}function V(){return Object.keys(T)}function ge(e){let t=H(e);if(!t)throw new Error(`Unknown provider: ${e}`);if(e==="mistral")return Le(t);switch(t.apiStyle){case"openai":case"anthropic":return Be(t);case"ollama":return Fe(t);case"gemini":return"";default:return""}}function Q(){return r.think==="false"||r.think==="0"}function Y(){return r.think!==""&&!Q()}function $e(e,t,n){let o=e;return r.think!==""&&n==="openai"&&(Q()?(o+=' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".',o+=" /no_think"):o="Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer."+o),t?o:r.prompt+Je()+o}function Je(){return`
.Translate the code into `+r.language+` programming language
`}function Ye(e,t,n,o){let i=r.model||e.defaultModel,a=$e(n,o,e.apiStyle),s=fe(e);if(t.requiresUrlApiKey&&s?.[1]&&e.authKey)return`Cannot read ~/.r2ai.${W(e.authKey)}-key`;let l=t.buildPayload(i,a),u=he(e,s?.[0]||null);e.apiStyle==="ollama"&&u.push("Accept: application/x-ndjson");let k=me(u),c=t.buildUrl(pe(e),i,s?.[0]||void 0);try{return t.parseResponse(de(c,k,JSON.stringify(l)))}catch(d){return"ERROR: "+d.message}}function ye(e,t){let n=H(r.api);return n?Ye(n,Ge[n.apiStyle],e,t):`Unknown value for 'decai -e api'. Available: ${V().join(", ")}`}function We(){return Object.fromEntries(Object.entries(T).filter(([,e])=>e.authKey).map(([e,t])=>[e,t.authKey]))}function K(e,t){let n=r2.cmd("'%"+t).trim();if(!n.includes("=")&&n!=="")return[n.trim(),null,"env"];let o=e.toLowerCase(),i=M;if(_(i)){let s=r2.cmd("'cat "+i),l=ae(s);if(o in l)return[l[o],null,"txt"]}let a="~/.r2ai."+o+"-key";if(_(a)){let s=r2.cmd("'cat "+a);return s===""?[null,"Cannot read "+a,"no"]:[s.trim(),null,"file"]}return[null,"Not available","nope"]}function be(){q(w,M),r2.cmd("'ed "+M)}function X(){Object.entries(We()).forEach(([e,t])=>{let n=K(e,t)[2];console.log(n,"	",e)})}function ke(e){let t=H(e);if(!t){console.error(`Unknown provider: ${e}`);return}try{let n=ge(e);n&&console.log(n),t.hardcodedModels&&t.hardcodedModels.forEach(o=>console.log(o)),e==="mistral"&&console.log("ministral-8b-latest"),!n&&!t.hardcodedModels&&console.log(t.defaultModel)}catch(n){let o=n;console.error(`Error listing models for ${e}:`,o.message),console.log(t.defaultModel)}}var Z=!1;function ze(e){return e==="true"||e==="1"}function S(e){let t=r;return{get:()=>t[e],set:n=>{t[e]=ze(n)}}}function P(e){let t=r;return{get:()=>t[e],set:n=>{t[e]=n}}}var xe={pipeline:{get:()=>r.pipeline,set:e=>{r.pipeline=e;try{r.decopipe=JSON.parse(r2.cmd("cat "+e))}catch(t){console.error(t)}}},model:{get:()=>r.model,set:e=>{e==="?"?ke(r.api):r.model=e.trim()}},deterministic:S("deterministic"),files:S("useFiles"),think:{get:()=>r.think||"false",set:e=>{r.think=e}},debug:S("debug"),timeout:{get:()=>r.timeout,set:e=>{r.timeout=Math.max(0,parseInt(e,10)||0)}},api:{get:()=>r.api,set:e=>{e==="?"?console.error(V().join(`
`)):r.api=e}},lang:P("language"),hlang:P("humanLanguage"),cache:S("cache"),cmds:P("commands"),tts:S("tts"),yolo:S("yolo"),prompt:P("prompt"),ctxfile:P("contextFile"),baseurl:P("baseurl"),headers:{get:()=>le(r.extraHeaders),set:e=>{r.extraHeaders=J(e)}},maxtokens:{get:()=>r.maxInputTokens,set:e=>{r.maxInputTokens=parseInt(e,10)||-1}}};function Ve(){let e={host:r.host,port:r.port,lastOutput:r.lastOutput};Object.assign(r,x,e),r.decopipe={...x.decopipe},r.extraHeaders=[...x.extraHeaders]}function Qe(e){let t=e.trim();return!t||t.startsWith("#")?null:t.startsWith("decai -e ")?t.slice(9).trim():t}function b(e){let t=e.indexOf("="),n=t===-1?e:e.slice(0,t),o=t===-1?void 0:e.slice(t+1),i=xe[n];if(!i){console.error("Unknown config key");return}typeof o<"u"?i.set(o):console.log(i.get())}function ve(){Object.entries(xe).forEach(([e,t])=>{let n=t.get();console.log("decai -e "+e+"="+n)})}function we(){if(Ve(),!_(I))return;let e=r2.call("cat "+I);for(let t of e.split(/\r?\n/)){let n=Qe(t);n&&n[0]!="#"&&b(n)}}function Ee(){Z||(we(),Z=!0)}function Ae(){q(w,I),r2.cmd("'ed "+I),we(),Z=!0}function f(e,t,n=!1){let o=(t||"").replace(/`/g,""),i=e.replace(/'/g,"");if(r.api==="r2"||r.api==="r2ai"){let s=te(".pdc.txt");ie(s,o);let l=i.startsWith("-")?i:["-i",s,i].join(" "),k=(r.baseurl?r.baseurl+"/cmd":r.host+":"+r.port+"/cmd")+"/"+encodeURIComponent(l),c=A(k,[]);return c.error?`Error: ${c.error}`:c.result||JSON.stringify(c)||"Cannot curl, use r2ai-server or r2ai -w"}if(i.startsWith("-"))return"";let a=i+`:
`+o;return r.maxInputTokens>0&&a.length>r.maxInputTokens&&(a=a.slice(0,r.maxInputTokens)),ye(a,n)}function Se(e){let t=r2.cmd("e scr.color");r2.cmd("e scr.color=0");try{return e()}finally{r2.cmd("e scr.color="+t)}}function Oe(){let e="",t=n=>e+=" "+y+" "+n+`
`;e+="Usage: "+y+` (-h) ...
`,e+="Version: "+ee+`
`,t("-a [query]    - solve query with auto mode"),t("-b [url]      - set base URL (alias for decai -e baseurl)"),t("-d [f1 ..]    - decompile given functions"),t("-dd [..]      - same as above, but ignoring cache"),t("-dD [query]   - decompile current function with given extra query"),t("-dr           - decompile function and its called ones (recursive)"),t("-e            - display and change eval config vars"),t("-E            - edit and run decai.txt"),t("-h            - show this help"),t("-H            - help setting up r2ai"),t("-i [f] [q]    - include given file and query"),t("-k            - list API key status"),t("-K            - edit apikeys.txt"),t("-m [model]    - use -m? or -e model=? to list the available models"),t("-n            - suggest better function name"),t("-p [provider] - same as decai -e api (will be provider)"),t("-q [text]     - query language model with given text"),t("-Q [text]     - query on top of the last output"),t("-r [prompt]   - change role prompt (same as: decai -e prompt)"),t("-R            - reset role prompt to default prompt"),t("-s            - function signature"),t("-v            - show local variables"),t("-V            - find vulnerabilities"),t("-x[*]         - eXplain current function (-x* for r2 script)"),r2.log(e.trim())}function D(e,t,n,o){if(n){let s=r2.cmd("anos").trim();if(s.length>0)return s}let i="";if(o){let s=r2.cmd("s");i+=`## Context functions:
`;let l=r2.cmdAt("axff~^C[2]~$$",s);for(let u of l.split(/\n/g))i+=r2.cmd("pdc@"+u);r2.cmd("s "+s)}let a=t?" "+e:"";try{let s=e.slice(2).trim(),l="";r.contextFile!==""&&r2.cmd2("test -f "+r.contextFile).value===0&&(l+=`## Context:
[START]
`+r2.cmd("cat "+r.contextFile)+`
[END]
`);let{body:u,count:k}=Se(()=>{let d=`## Before:
`,g=0;for(let h of r.commands.split(",")){if(h.trim()==="")continue;let C=t||s.trim().length===0?h:h+"@@= "+s,R=r2.cmd(C);R.length>5&&(d+="Output of "+h+`:
[START]
`+R+`
[END]
`,g++)}return d+=`## After:
`,{body:d,count:g}});if(k===0){console.error("Nothing to do.");return}let c="";if(r.decopipe.use){let d=r.model;try{let g=r.decopipe[r.decopipe.default],h=l+u;for(let C of g.pipeline){C.model&&(r.model=C.model);let R=C.query+". "+g.globalQuery;c=f(R,h,!0),r.debug&&console.log(`QUERY
`,R,`
INPUT
`,h,`
OUTPUT
`,c),h=c}c=h}finally{r.model=d}}else{let d=a;l+=u+i,c=f(d,l,!1),r.lastOutput=c}return n&&c.length>1&&r2.call("ano=base64:"+G(c)),c.startsWith("```")&&(c=c.replace(/```.*\n/,"").replace(/```$/,"")),c.trim()}catch(s){let l=s;console.error(l,l.stack);return}}function Xe(){let e=Se(()=>"[START]"+r.commands.split(",").map(o=>r2.cmd(o)).join(`
`)+"[END]"),n=f("Analyze function calls, references, comments and strings, loops and ignore registers and memory accesses. Explain the purpose of this function in a single short sentence. /no_think Do not introduce or argue the response, translation of the explanation in "+r.humanLanguage,e,!0).trim().split(/\n/g);return n[n.length-1].trim()}function Ze(){let e=r.language,t=r2.cmd("afv;pdc");r.language="C";let n="'afs "+f("analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the return. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",t,!1),o=n.indexOf("{");return o!==-1&&(n=n.substring(0,o)),r.language=e,n}function et(e,t){let n=[];for(;;){let o=F.auto;if(n.length>0){o+=`## Command Results

`;for(let a of n){let s=JSON.parse(a);o+="### "+s.command+"\n\n```\n"+s.response+"\n```\n"}}o+=`

## User Prompt

`+e,r.debug&&console.log(`#### input
`,o,`
#### /input`),console.log("Thinking...");let i=f("",o,!0);r.debug&&console.log(`#### output
`,i,`
#### /output`);try{let a=JSON.parse(re(oe(v(i))));if(a.action==="r2cmd"||a.action==="response"||a.action===a.command){let s=a.command||"";a.reason&&(console.log("[r2cmd] Reasoning: "+a.reason),r.tts&&(r2.syscmd("pkill say"),r2.syscmd("say -v Alex -r 250 '"+a.reason.replace(/'/g,"")+"' &"))),console.log("[r2cmd] Action: "+a.description),console.log("[r2cmd] Command: "+s);let l=s;r.yolo||(l=tt(s,t)),console.log("[r2cmd] Running: "+l);let u=r2.cmd2(l),k=u.logs?u.logs.map(g=>g.type+": "+g.message).join(`
`):"",c=(u.res+k).trim();console.log(c);let d=ne(c);r.debug&&console.log(`<r2output>
`,d,`
<(r2output>`),n.push(JSON.stringify({action:"response",command:l,description:a.description,response:d}))}else if(a.action==="reply"){console.log(`Done
`,a.response);break}else{console.log(`Unknown response
`,JSON.stringify(i));break}}catch(a){let s=i.indexOf('response": "');if(s!==-1){let l=i.slice(s+12).replace(/\\n/g,`
`).replace(/\\/g,"");console.log(l)}else console.log(i),console.error(a);break}}}function tt(e,t){for(;;){let n=r2.cmd("'?ie Tweak command? ('?' for help)").trim();if(n==="q!"){console.error("Break!");break}if(n==="?"){nt();continue}else if(n.startsWith(":")){console.log(r2.cmd(n.slice(1)));continue}else if(n.startsWith("-e")){t(n);continue}else{if(n==="!")return"?e do NOT execute '"+e+"' again, continue without it";if(n.startsWith("!")){console.log(r2.syscmd(n.slice(1)));continue}else{if(n==="q")return"?e All data collected!. Do not call more commands, reply the solutions";if(n){let o=n.indexOf("#");return o!==-1?n.slice(0,o).trim():n}else return e}}}return e}function nt(){console.log(" '!'     do not run this command"),console.log(" '!c'    run system command"),console.log(" 'q'     to quit auto and try to solve"),console.log(" 'q!'    quit auto without solving"),console.log(" 'c # C' use given command with comment"),console.log(" ':c'    run r2 command without feeding auto"),console.log(" '-e'    set decai configuration variables")}function ot(e){return e.slice(2).trim()}function j(){return r2.cmd("afi.").trim().length>0}var B="Cannot find function at current offset";function Pe(e,t){if(e===""||!e.startsWith("-")){Oe();return}let n="",o=e[1],i=ot(e);switch(o){case"H":console.log(F.decai);break;case"a":et(i,t);break;case"m":{i==="="?b("model="):i?b("model="+i):b("model");break}case"n":case"f":{if(!j()){n=B;break}n=r2.cmd("axff~$[3]");let a=r2.cmd("fd.").trim().split(/\n/).filter(s=>!s.startsWith("secti")).join(",");n=f("give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: "+a,n,!1).trim(),n+=" @ "+r2.cmd("?v $FB").trim();break}case"v":{if(!j()){n=B;break}n=r2.cmd("afv;pdc"),n=f("guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",n,!1);break}case"i":{let a=i.split(/\s+/).filter(Boolean);if(a.length>=2){let s=a[0],l=a.slice(1).join(" "),u=r2.cmd("cat "+s);console.log(f(l,u,!0))}else console.log("Use: decai -i [file] [query ...]");break}case"p":{i?b("api="+i):X();break}case"r":{i?r.prompt=i:console.log(r.prompt);break}case"R":r.prompt=N;break;case"s":if(!j()){n=B;break}n=Ze();break;case"V":n=f("find vulnerabilities, dont show the code, only show the response, provide a sample exploit",r.lastOutput,!1);break;case"K":be();break;case"E":Ae();break;case"k":X();break;case"b":{i?b("baseurl="+i):console.log(r.baseurl);break}case"e":{i?b(i):ve();break}case"q":try{n=f(i,null,!0)}catch(a){let s=a;console.error(s,s.stack)}break;case"Q":n=f(i,r.lastOutput,!1);break;case"x":if(!j()){n=B;break}n=Xe(),(e[2]==="*"||e[2]==="r")&&(n="'CC "+n);break;case"d":e[2]==="r"?n=D(e.slice(2),!0,r.cache,!0)||"":e[2]==="d"?n=D(e,!1,!1,!1)||"":e[2]==="D"?n=D(e,!0,!1,!1)||"":n=D(e,!1,r.cache,!1)||"";break;default:Oe();break}return n||void 0}function Ce(e){Ee();let t=Pe(e,Ce);return t&&r2.log(t),!0}function rt(){r2.unload("core",y),r2.plugin("core",function(){function e(t){if(t.startsWith(y)){let n=t.slice(y.length).trim();return Ce(n)}return!1}return{name:y,license:"MIT",desc:"r2 decompiler based on r2ai",call:e}})}rt();
