📦
27073 /main.js
✄
var ee="1.4.0",y="decai",A="~/.config/r2ai",M=A+"/apikeys.txt",R=A+"/decai.txt",N="Rewrite this pseudocode into concise and clean code. Output only the provided function. Do not add wrappers, helper examples, test code, or main-like functions. Replace goto with structured control flow, simplify as much as possible, infer types and use better names for variables and parameters, some strings may be appearing as comments, preserve only what is implied by the input, and remove dead code.",F={decai:`# Using Decai

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
* 'decai -e apitype=chat|generate' choose the Ollama API endpoint (default: chat)
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
`};var v={decopipe:{use:!1},host:"http://localhost",port:"11434",baseurl:"",extraHeaders:[],api:"ollama",pipeline:"",commands:"pdc",yolo:!1,tts:!1,language:"C",humanLanguage:"English",deterministic:!0,debug:!1,timeout:180,think:"",apitype:"chat",useFiles:!1,contextFile:"",model:"",cache:!1,maxInputTokens:-1,prompt:N,lastOutput:""},o={...v,decopipe:{...v.decopipe},extraHeaders:[...v.extraHeaders]};function te(e){return(r2.cmd("-e dir.tmp").trim()??".")+"/"+e}function T(e,t){r2.cmd("'mkdir -p "+e),r2.cmd("'touch "+t)}function _(e){return(r2.cmd2("test -h").logs?.[0]?.message??"").includes("-fdx")?!0:r2.cmd("'test -vf "+e).startsWith("found")}function L(e,t){return e+" ".repeat(Math.max(0,t-e.length))}function ne(e){return e.replace(/\x1b\[[0-9;]*m/g,"")}function oe(e){let t=e.match(/```json\s*([\s\S]*?)```/);return t&&t[1]?t[1].trim():e}function re(e){let t=e,n=t.indexOf("{");n!==-1&&(t=t.slice(n));let r=t.lastIndexOf("}");return r!==-1&&(t=t.slice(0,r+1)),t}function G(e){return btoa(e)}function ie(e,t){let n=G(t);r2.cmd("p6ds "+n+" > "+e)}function b(e){let t=e;return t=t.replace(/<think>[\s\S]*?<\/think>/gi,""),t.split(`
`).filter(n=>!n.trim().startsWith("```")).join(`
`)}function $(e){o.debug&&console.log(e)}function ae(e){let t={};for(let n of e.split(/\r?\n/)){let r=n.trim();if(!r||r.startsWith("#"))continue;let[i,...a]=r.split("=");if(!i||a.length===0)continue;let s=a.join("=").trim(),l=i.toLowerCase().replace(/_api_key$/i,"");t[l]=s}return t}var Ie=["DECAI_HEADERS","R2AI_HEADERS"];function Re(e){let t=r2.cmd("'%"+e).trim();return t!==""&&!t.includes("=")?t:""}function _e(e){return e.trim().toLowerCase()}function Ue(e){let t=e.indexOf(":"),n=e.indexOf("="),r=t!==-1&&(n===-1||t<n)?t:n;if(r===-1)return null;let i=e.slice(0,r).trim();return i===""?null:{name:i,value:e.slice(r+1).trim()}}function Me(e){return e.value===""?`${e.name}:`:`${e.name}: ${e.value}`}function se(e,t){for(let n of e){let r=Ue(n.trim());r&&t.set(_e(r.name),Me(r))}}function J(e){let t=new Map,n=e.replace(/\\n/g,`
`).split(/\r?\n/g).filter(r=>{let i=r.trim();return i&&!i.startsWith("#")});return se(n,t),Array.from(t.values())}function le(e){return e.join("\\n")}function w(...e){let t=new Map;for(let n of e)se(n,t);return Array.from(t.values())}function Ne(){for(let e of Ie){let t=Re(e);if(t)return J(t)}return[]}function ce(){return w(Ne(),o.extraHeaders)}function U(e){return`'${e.replace(/'/g,`'"'"'`)}'`}function Te(e){let{method:t,url:n,headers:r,payload:i}=e,a=["curl","-s"];if(o.timeout>0&&a.push("--max-time",String(o.timeout)),w(["Content-Type: application/json"],r).forEach(l=>a.push("-H",U(l))),t==="POST"){if(!i)throw new Error("Payload required for POST requests");let l=r2.fdump(i);a.push("--data-binary","@"+U(l),U(n));let u=a.join(" ")+"; rm "+U(l);return $(u),r2.syscmds(u)}else{a.push(U(n));let l=a.join(" ");return $(l),r2.syscmds(l)}}function Ke(e){let t=e.split(`
`).filter(i=>i.trim()!=="");if(t.length<=1)return null;let n="",r=null;for(let i of t)try{let a=JSON.parse(i);if(a.error)return a;a.message?.content!==void 0&&(n+=a.message.content),r=a}catch{return null}return r?(r.message={role:"assistant",content:n},r):null}function ue(e){try{let t=Te(e).trim();if(t==="")return{error:"empty response"};try{return JSON.parse(t)}catch{let n=Ke(t);return n||{error:t,rawOutput:t}}}catch(t){return{error:t.message}}}function E(e,t){return ue({method:"GET",url:e,headers:t})}function de(e,t,n){return ue({method:"POST",url:e,headers:t,payload:n})}function W(e){return e.split("_")[0].toLowerCase()}function pe(e){if(!e.authKey)return;let t=Array.from(new Set([e.keyName,W(e.authKey)].filter(Boolean))),n;for(let r of t){let i=K(r,e.authKey);if(i[0])return i;!n&&i[2]!=="nope"&&(n=i)}return n||K(W(e.authKey),e.authKey)}function O(e){if(e)return typeof e=="string"?e:e.message||JSON.stringify(e)}function fe(e){return o.baseurl||e.defaultBaseUrl}function me(e,t=ce()){return w(e,t)}function qe(e){return e?["Authorization: Bearer "+e]:[]}function He(e){let t=["anthropic-version: 2023-06-01"];return e?w(t,["x-api-key: "+e]):t}function he(e,t){switch(e.authStyle||"none"){case"bearer":return qe(t);case"anthropic":return He(t);case"none":default:return[]}}function De(e,t,n){let r=E(e,t),i=O(r.error);return i?(console.error(i),"error invalid response"):r.data?.map(n).join(`
`)||""}function je(e,t){let n=new Set;return e.filter(r=>{let i=t(r);return n.has(i)?!1:(n.add(i),!0)})}function z(e){let t=pe(e)?.[0]||null;return{baseUrl:fe(e),headers:me(he(e,t))}}function Be(e){let{baseUrl:t,headers:n}=z(e);return De(t+"/v1/models",n,r=>r.id)}function Fe(e){let{baseUrl:t,headers:n}=z(e),r=E(t+"/api/tags",n),i=O(r.error);return i?(console.error(i),"error invalid response"):r.models?.map(a=>a.name).join(`
`)||""}function Le(e){let{baseUrl:t,headers:n}=z(e),r=E(t+"/v1/models",n);return r.data?je(r.data,i=>i.name||i.id).map(i=>[L(i.name||i.id,30),L(""+(i.max_context_length||""),10),i.description||""].join(" ")).join(`
`):""}var Ge={openai:{buildPayload:(e,t)=>({stream:!1,model:e,messages:[{role:"user",content:t}]}),parseResponse:e=>{if(e.error)throw new Error(O(e.error)||"Unknown error");if(e.choices&&e.choices[0]?.message?.content)return b(e.choices[0].message.content);throw new Error("Invalid response format")},buildUrl:e=>e+"/v1/chat/completions"},anthropic:{buildPayload:(e,t)=>{let n={model:e,max_tokens:5128,messages:[{role:"user",content:t}]};return Y()&&(n.thinking={type:"enabled",budget_tokens:4096},n.max_tokens=16e3),o.deterministic&&!Y()&&Object.assign(n,{temperature:0,top_p:0,top_k:1}),n},parseResponse:e=>{if(e.content&&Array.isArray(e.content)){let t=[];for(let n of e.content)n.text&&t.push(n.text);if(t.length>0)return b(t.join(`
`))}throw e.error?new Error(O(e.error)||"Unknown error"):new Error("Invalid response format")},buildUrl:e=>e+"/v1/messages"},ollama:{buildPayload:(e,t)=>{let n={stream:!1,model:e};return o.apitype==="generate"?n.prompt=t:n.messages=[{role:"user",content:t}],Y()?o.think==="true"||o.think==="1"?n.think=!0:n.think=o.think:n.think=!1,o.deterministic&&(n.options={repeat_last_n:0,top_p:1,top_k:1,temperature:0,repeat_penalty:1,seed:123}),n},parseResponse:e=>{if(e.error)throw new Error(O(e.error));if(typeof e.response=="string")return b(e.response);if(e.message?.content)return b(e.message.content);throw new Error(JSON.stringify(e))},buildUrl:e=>e+"/api/"+o.apitype},gemini:{buildPayload:(e,t)=>{let n={contents:[{parts:[{text:t}]}]},r={};return o.deterministic&&Object.assign(r,{temperature:0,topP:1,topK:1}),o.think!==""&&(Q()?r.thinkingConfig={thinkingBudget:0}:r.thinkingConfig={thinkingBudget:8192}),Object.keys(r).length>0&&(n.generationConfig=r),n},parseResponse:e=>{if(e.candidates&&e.candidates[0]?.content?.parts){let n=e.candidates[0].content.parts.filter(r=>!r.thought&&r.text).map(r=>r.text);if(n.length>0)return b(n.join(`
`))}throw e.error?new Error(O(e.error)):(console.log(JSON.stringify(e)),new Error("Invalid response format"))},buildUrl:(e,t,n)=>`${e}/v1beta/models/${t}:generateContent?key=${n}`,requiresUrlApiKey:!0}},q={anthropic:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseUrl:"https://api.anthropic.com",authKey:"ANTHROPIC_API_KEY",keyName:"anthropic",authStyle:"anthropic",apiStyle:"anthropic"},claude:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseUrl:"https://api.anthropic.com",authKey:"ANTHROPIC_API_KEY",keyName:"claude",authStyle:"anthropic",apiStyle:"anthropic"},openai:{defaultModel:"gpt-4o-mini",defaultBaseUrl:"https://api.openai.com",authKey:"OPENAI_API_KEY",authStyle:"bearer",apiStyle:"openai"},ollama:{defaultModel:"qwen2.5-coder:latest",defaultBaseUrl:"http://localhost:11434",authStyle:"none",apiStyle:"ollama"},ollamacloud:{defaultModel:"gpt-oss:120b",defaultBaseUrl:"https://ollama.com",authKey:"OLLAMA_API_KEY",keyName:"ollamacloud",authStyle:"bearer",apiStyle:"ollama"},zen:{defaultModel:"big-pickle",defaultBaseUrl:"https://opencode.ai/zen",authKey:"OPENCODE_API_KEY",keyName:"zen",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["big-pickle","glm-5","kimi-k2.5"]},gemini:{defaultModel:"gemini-2.5-flash",defaultBaseUrl:"https://generativelanguage.googleapis.com",authKey:"GEMINI_API_KEY",authStyle:"none",apiStyle:"gemini",hardcodedModels:["gemini-2.0-flash","gemini-2.0-flash-lite","gemini-2.5-pro","gemini-2.5-flash","gemini-2.5-flash-lite"]},mistral:{defaultModel:"codestral-latest",defaultBaseUrl:"https://api.mistral.ai",authKey:"MISTRAL_API_KEY",authStyle:"bearer",apiStyle:"openai"},xai:{defaultModel:"grok-beta",defaultBaseUrl:"https://api.x.ai",authKey:"XAI_API_KEY",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["grok-2","grok-beta"]},lmstudio:{defaultModel:"local-model",defaultBaseUrl:"http://127.0.0.1:1234",authStyle:"none",apiStyle:"openai"},deepseek:{defaultModel:"deepseek-coder",defaultBaseUrl:"https://api.deepseek.com",authKey:"DEEPSEEK_API_KEY",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["deepseek-coder","deepseek-chat"]},openrouter:{defaultModel:"openai/gpt-4o-mini",defaultBaseUrl:"https://openrouter.ai/api",authKey:"OPENROUTER_API_KEY",authStyle:"bearer",apiStyle:"openai"},groq:{defaultModel:"llama-3.3-70b-versatile",defaultBaseUrl:"https://api.groq.com/openai",authKey:"GROQ_API_KEY",authStyle:"bearer",apiStyle:"openai"}};function H(e){return q[e]}function V(){return Object.keys(q)}function ge(e){let t=H(e);if(!t)throw new Error(`Unknown provider: ${e}`);if(e==="mistral")return Le(t);switch(t.apiStyle){case"openai":case"anthropic":return Be(t);case"ollama":return Fe(t);case"gemini":return"";default:return""}}function Q(){return o.think==="false"||o.think==="0"}function Y(){return o.think!==""&&!Q()}function $e(e,t,n){let r=e;return o.think!==""&&n==="openai"&&(Q()?(r+=' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".',r+=" /no_think"):r="Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer."+r),t?r:o.prompt+Je()+r}function Je(){return`
.Translate the code into `+o.language+` programming language
`}function Ye(e,t,n,r){let i=o.model||e.defaultModel,a=$e(n,r,e.apiStyle),s=pe(e);if(t.requiresUrlApiKey&&s?.[1]&&e.authKey)return`Cannot read ~/.r2ai.${W(e.authKey)}-key`;let l=t.buildPayload(i,a),u=he(e,s?.[0]||null);e.apiStyle==="ollama"&&u.push("Accept: application/x-ndjson");let x=me(u),c=t.buildUrl(fe(e),i,s?.[0]||void 0);try{return t.parseResponse(de(c,x,JSON.stringify(l)))}catch(d){return"ERROR: "+d.message}}function ye(e,t){let n=H(o.api);return n?Ye(n,Ge[n.apiStyle],e,t):`Unknown value for 'decai -e api'. Available: ${V().join(", ")}`}function We(){return Object.fromEntries(Object.entries(q).filter(([,e])=>e.authKey).map(([e,t])=>[e,t.authKey]))}function K(e,t){let n=r2.cmd("'%"+t).trim();if(!n.includes("=")&&n!=="")return[n.trim(),null,"env"];let r=e.toLowerCase(),i=M;if(_(i)){let s=r2.cmd("'cat "+i),l=ae(s);if(r in l)return[l[r],null,"txt"]}let a="~/.r2ai."+r+"-key";if(_(a)){let s=r2.cmd("'cat "+a);return s===""?[null,"Cannot read "+a,"no"]:[s.trim(),null,"file"]}return[null,"Not available","nope"]}function be(){T(A,M),r2.cmd("'ed "+M)}function X(){Object.entries(We()).forEach(([e,t])=>{let n=K(e,t)[2];console.log(n,"	",e)})}function ke(e){let t=H(e);if(!t){console.error(`Unknown provider: ${e}`);return}try{let n=ge(e);n&&console.log(n),t.hardcodedModels&&t.hardcodedModels.forEach(r=>console.log(r)),e==="mistral"&&console.log("ministral-8b-latest"),!n&&!t.hardcodedModels&&console.log(t.defaultModel)}catch(n){let r=n;console.error(`Error listing models for ${e}:`,r.message),console.log(t.defaultModel)}}var Z=!1;function ze(e){return e==="true"||e==="1"}function S(e){let t=o;return{get:()=>t[e],set:n=>{t[e]=ze(n)}}}function P(e){let t=o;return{get:()=>t[e],set:n=>{t[e]=n}}}function Ve(e){let t=e.trim();return t==="chat"?"chat":t==="generate"?"generate":null}var xe={pipeline:{get:()=>o.pipeline,set:e=>{o.pipeline=e;try{o.decopipe=JSON.parse(r2.cmd("cat "+e))}catch(t){console.error(t)}}},model:{get:()=>o.model,set:e=>{e==="?"?ke(o.api):o.model=e.trim()}},deterministic:S("deterministic"),files:S("useFiles"),think:{get:()=>o.think||"false",set:e=>{o.think=e}},apitype:{get:()=>o.apitype,set:e=>{let t=Ve(e);t?o.apitype=t:console.error("Invalid apitype. Use chat or generate.")}},debug:S("debug"),timeout:{get:()=>o.timeout,set:e=>{o.timeout=Math.max(0,parseInt(e,10)||0)}},api:{get:()=>o.api,set:e=>{e==="?"?console.error(V().join(`
`)):o.api=e}},lang:P("language"),hlang:P("humanLanguage"),cache:S("cache"),cmds:P("commands"),tts:S("tts"),yolo:S("yolo"),prompt:P("prompt"),ctxfile:P("contextFile"),baseurl:P("baseurl"),headers:{get:()=>le(o.extraHeaders),set:e=>{o.extraHeaders=J(e)}},maxtokens:{get:()=>o.maxInputTokens,set:e=>{o.maxInputTokens=parseInt(e,10)||-1}}};function Qe(){let e={host:o.host,port:o.port,lastOutput:o.lastOutput};Object.assign(o,v,e),o.decopipe={...v.decopipe},o.extraHeaders=[...v.extraHeaders]}function Xe(e){let t=e.trim();return!t||t.startsWith("#")?null:t.startsWith("decai -e ")?t.slice(9).trim():t}function k(e){let t=e.indexOf("="),n=t===-1?e:e.slice(0,t),r=t===-1?void 0:e.slice(t+1),i=xe[n];if(!i){console.error("Unknown config key");return}typeof r<"u"?i.set(r):console.log(i.get())}function ve(){Object.entries(xe).forEach(([e,t])=>{let n=t.get();console.log("decai -e "+e+"="+n)})}function Ae(){if(Qe(),!_(R))return;let e=r2.call("cat "+R);for(let t of e.split(/\r?\n/)){let n=Xe(t);n&&n[0]!="#"&&k(n)}}function we(){Z||(Ae(),Z=!0)}function Ee(){T(A,R),r2.cmd("'ed "+R),Ae(),Z=!0}function p(e,t,n=!1){let r=(t||"").replace(/`/g,""),i=e.replace(/'/g,"");if(o.api==="r2"||o.api==="r2ai"){let s=te(".pdc.txt");ie(s,r);let l=i.startsWith("-")?i:["-i",s,i].join(" "),x=(o.baseurl?o.baseurl+"/cmd":o.host+":"+o.port+"/cmd")+"/"+encodeURIComponent(l),c=E(x,[]);return c.error?`Error: ${c.error}`:c.result||JSON.stringify(c)||"Cannot curl, use r2ai-server or r2ai -w"}if(i.startsWith("-"))return"";let a=i+`:
`+r;return o.maxInputTokens>0&&a.length>o.maxInputTokens&&(a=a.slice(0,o.maxInputTokens)),ye(a,n)}function Se(e){let t=r2.cmd("e scr.color");r2.cmd("e scr.color=0");try{return e()}finally{r2.cmd("e scr.color="+t)}}function Oe(){let e="",t=n=>e+=" "+y+" "+n+`
`;e+="Usage: "+y+` (-h) ...
`,e+="Version: "+ee+`
`,t("-a [query]    - solve query with auto mode"),t("-b [url]      - set base URL (alias for decai -e baseurl)"),t("-d [f1 ..]    - decompile given functions"),t("-dd [..]      - same as above, but ignoring cache"),t("-dD [query]   - decompile current function with given extra query"),t("-dr           - decompile function and its called ones (recursive)"),t("-e            - display and change eval config vars"),t("-E            - edit and run decai.txt"),t("-h            - show this help"),t("-H            - help setting up r2ai"),t("-i [f] [q]    - include given file and query"),t("-k            - list API key status"),t("-K            - edit apikeys.txt"),t("-m [model]    - use -m? or -e model=? to list the available models"),t("-n            - suggest better function name"),t("-p [provider] - same as decai -e api (will be provider)"),t("-q [text]     - query language model with given text"),t("-Q [text]     - query on top of the last output"),t("-r [prompt]   - change role prompt (same as: decai -e prompt)"),t("-R            - reset role prompt to default prompt"),t("-s            - function signature"),t("-v            - show local variables"),t("-V            - find vulnerabilities"),t("-x[*]         - eXplain current function (-x* for r2 script)"),r2.log(e.trim())}function D(e,t,n,r){if(n){let s=r2.cmd("anos").trim();if(s.length>0)return s}let i="";if(r){let s=r2.cmd("s");i+=`## Context functions:
`;let l=r2.cmdAt("axff~^C[2]~$$",s);for(let u of l.split(/\n/g))i+=r2.cmd("pdc@"+u);r2.cmd("s "+s)}let a=t?" "+e:"";try{let s=e.slice(2).trim(),l="";o.contextFile!==""&&r2.cmd2("test -f "+o.contextFile).value===0&&(l+=`## Context:
[START]
`+r2.cmd("cat "+o.contextFile)+`
[END]
`);let{body:u,count:x}=Se(()=>{let d=`## Before:
`,g=0;for(let h of o.commands.split(",")){if(h.trim()==="")continue;let C=t||s.trim().length===0?h:h+"@@= "+s,I=r2.cmd(C);I.length>5&&(d+="Output of "+h+`:
[START]
`+I+`
[END]
`,g++)}return d+=`## After:
`,{body:d,count:g}});if(x===0){console.error("Nothing to do.");return}let c="";if(o.decopipe.use){let d=o.model;try{let g=o.decopipe[o.decopipe.default],h=l+u;for(let C of g.pipeline){C.model&&(o.model=C.model);let I=C.query+". "+g.globalQuery;c=p(I,h,!0),o.debug&&console.log(`QUERY
`,I,`
INPUT
`,h,`
OUTPUT
`,c),h=c}c=h}finally{o.model=d}}else{let d=a;l+=u+i,c=p(d,l,!1),o.lastOutput=c}return n&&c.length>1&&r2.call("ano=base64:"+G(c)),c.startsWith("```")&&(c=c.replace(/```.*\n/,"").replace(/```$/,"")),c.trim()}catch(s){let l=s;console.error(l,l.stack);return}}function Ze(){let e=Se(()=>"[START]"+o.commands.split(",").map(r=>r2.cmd(r)).join(`
`)+"[END]"),n=p("Analyze function calls, references, comments and strings, loops and ignore registers and memory accesses. Explain the purpose of this function in a single short sentence. /no_think Do not introduce or argue the response, translation of the explanation in "+o.humanLanguage,e,!0).trim().split(/\n/g);return n[n.length-1].trim()}function et(){let e=o.language,t=r2.cmd("afv;pdc");o.language="C";let n="'afs "+p("analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the return. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",t,!1),r=n.indexOf("{");return r!==-1&&(n=n.substring(0,r)),o.language=e,n}function tt(e,t){let n=[];for(;;){let r=F.auto;if(n.length>0){r+=`## Command Results

`;for(let a of n){let s=JSON.parse(a);r+="### "+s.command+"\n\n```\n"+s.response+"\n```\n"}}r+=`

## User Prompt

`+e,o.debug&&console.log(`#### input
`,r,`
#### /input`),console.log("Thinking...");let i=p("",r,!0);o.debug&&console.log(`#### output
`,i,`
#### /output`);try{let a=JSON.parse(re(oe(b(i))));if(a.action==="r2cmd"||a.action==="response"||a.action===a.command){let s=a.command||"";a.reason&&(console.log("[r2cmd] Reasoning: "+a.reason),o.tts&&(r2.syscmd("pkill say"),r2.syscmd("say -v Alex -r 250 '"+a.reason.replace(/'/g,"")+"' &"))),console.log("[r2cmd] Action: "+a.description),console.log("[r2cmd] Command: "+s);let l=s;o.yolo||(l=nt(s,t)),console.log("[r2cmd] Running: "+l);let u=r2.cmd2(l),x=u.logs?u.logs.map(g=>g.type+": "+g.message).join(`
`):"",c=(u.res+x).trim();console.log(c);let d=ne(c);o.debug&&console.log(`<r2output>
`,d,`
<(r2output>`),n.push(JSON.stringify({action:"response",command:l,description:a.description,response:d}))}else if(a.action==="reply"){console.log(`Done
`,a.response);break}else{console.log(`Unknown response
`,JSON.stringify(i));break}}catch(a){let s=i.indexOf('response": "');if(s!==-1){let l=i.slice(s+12).replace(/\\n/g,`
`).replace(/\\/g,"");console.log(l)}else console.log(i),console.error(a);break}}}function nt(e,t){for(;;){let n=r2.cmd("'?ie Tweak command? ('?' for help)").trim();if(n==="q!"){console.error("Break!");break}if(n==="?"){ot();continue}else if(n.startsWith(":")){console.log(r2.cmd(n.slice(1)));continue}else if(n.startsWith("-e")){t(n);continue}else{if(n==="!")return"?e do NOT execute '"+e+"' again, continue without it";if(n.startsWith("!")){console.log(r2.syscmd(n.slice(1)));continue}else{if(n==="q")return"?e All data collected!. Do not call more commands, reply the solutions";if(n){let r=n.indexOf("#");return r!==-1?n.slice(0,r).trim():n}else return e}}}return e}function ot(){console.log(" '!'     do not run this command"),console.log(" '!c'    run system command"),console.log(" 'q'     to quit auto and try to solve"),console.log(" 'q!'    quit auto without solving"),console.log(" 'c # C' use given command with comment"),console.log(" ':c'    run r2 command without feeding auto"),console.log(" '-e'    set decai configuration variables")}function rt(e){return e.slice(2).trim()}function j(){return r2.cmd("afi.").trim().length>0}var B="Cannot find function at current offset";function Pe(e,t){if(e===""||!e.startsWith("-")){Oe();return}let n="",r=e[1],i=rt(e);switch(r){case"H":console.log(F.decai);break;case"a":tt(i,t);break;case"m":{i==="="?k("model="):i?k("model="+i):k("model");break}case"n":case"f":{if(!j()){n=B;break}n=r2.cmd("axff~$[3]");let a=r2.cmd("fd.").trim().split(/\n/).filter(s=>!s.startsWith("secti")).join(",");n=p("give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: "+a,n,!1).trim(),n+=" @ "+r2.cmd("?v $FB").trim();break}case"v":{if(!j()){n=B;break}n=r2.cmd("afv;pdc"),n=p("guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",n,!1);break}case"i":{let a=i.split(/\s+/).filter(Boolean);if(a.length>=2){let s=a[0],l=a.slice(1).join(" "),u=r2.cmd("cat "+s);console.log(p(l,u,!0))}else console.log("Use: decai -i [file] [query ...]");break}case"p":{i?k("api="+i):X();break}case"r":{i?o.prompt=i:console.log(o.prompt);break}case"R":o.prompt=N;break;case"s":if(!j()){n=B;break}n=et();break;case"V":n=p("find vulnerabilities, dont show the code, only show the response, provide a sample exploit",o.lastOutput,!1);break;case"K":be();break;case"E":Ee();break;case"k":X();break;case"b":{i?k("baseurl="+i):console.log(o.baseurl);break}case"e":{i?k(i):ve();break}case"q":try{n=p(i,null,!0)}catch(a){let s=a;console.error(s,s.stack)}break;case"Q":n=p(i,o.lastOutput,!1);break;case"x":if(!j()){n=B;break}n=Ze(),(e[2]==="*"||e[2]==="r")&&(n="'CC "+n);break;case"d":e[2]==="r"?n=D(e.slice(2),!0,o.cache,!0)||"":e[2]==="d"?n=D(e,!1,!1,!1)||"":e[2]==="D"?n=D(e,!0,!1,!1)||"":n=D(e,!1,o.cache,!1)||"";break;default:Oe();break}return n||void 0}function Ce(e){we();let t=Pe(e,Ce);return t&&r2.log(t),!0}function it(){r2.unload("core",y),r2.plugin("core",function(){function e(t){if(t.startsWith(y)){let n=t.slice(y.length).trim();return Ce(n)}return!1}return{name:y,license:"MIT",desc:"r2 decompiler based on r2ai",call:e}})}it();
