📦
26433 /main.js
✄
var X="1.3.2",b="decai",A="~/.config/r2ai",N=A+"/apikeys.txt",P=A+"/decai.txt",K="Rewrite this pseudocode into concise and clean code. Output only the provided function. Do not add wrappers, helper examples, test code, or main-like functions. Replace goto with structured control flow, simplify as much as possible, infer types and use better names for variables and parameters, some strings may be appearing as comments, preserve only what is implied by the input, and remove dead code.",B={decai:`# Using Decai

Decai is the radare2 plugin for decompiling functions with the help of language models.

By default uses a local ollama server, but can you can pick any other service by using 'decai -e api=?'.

[0x00000000]> decai -e api=?
r2ai deepseek anthropic gemini hf mistral ollama openapi openai vllm xai

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
`};var c={decopipe:{use:!1},host:"http://localhost",port:"11434",baseurl:"",extraHeaders:[],api:"ollama",pipeline:"",commands:"pdc",yolo:!1,tts:!1,language:"C",humanLanguage:"English",deterministic:!0,debug:!1,timeout:180,think:-1,useFiles:!1,contextFile:"",model:"",cache:!1,maxInputTokens:-1,prompt:K,lastOutput:""},n={...c,decopipe:{...c.decopipe},extraHeaders:[...c.extraHeaders]};function Z(e){return(r2.cmd("-e dir.tmp").trim()??".")+"/"+e}function U(e){r2.cmd("'mkdir -p "+e)}function D(e){r2.cmd("'touch "+e)}function O(e){return(r2.cmd2("test -h").logs?.[0]?.message??"").includes("-fdx")?!0:r2.cmd("'test -vf "+e).startsWith("found")}function Y(e,t){return e+" ".repeat(Math.max(0,t-e.length))}function ee(e){return e.replace(/\x1b\[[0-9;]*m/g,"")}function te(e){let t=e.match(/```json\s*([\s\S]*?)```/);return t&&t[1]?t[1].trim():e}function oe(e){let t=e,o=t.indexOf("{");o!==-1&&(t=t.slice(o));let i=t.lastIndexOf("}");return i!==-1&&(t=t.slice(0,i+1)),t}function j(e){return btoa(e)}function ne(e,t){let o=j(t);r2.cmd("p6ds "+o+" > "+e)}function E(e){let t=e;return n.think!==2&&(t=t.replace(/<think>[\s\S]*?<\/think>/gi,"")),t.split(`
`).filter(o=>!o.trim().startsWith("```")).join(`
`)}function G(e){n.debug&&console.log(e)}function re(e){let t={};for(let o of e.split(/\r?\n/)){let i=o.trim();if(!i||i.startsWith("#"))continue;let[r,...a]=i.split("=");if(!r||a.length===0)continue;let l=a.join("=").trim(),s=r.toLowerCase().replace(/_api_key$/i,"");t[s]=l}return t}var Oe={mistral:"MISTRAL_API_KEY",anthropic:"ANTHROPIC_API_KEY",huggingface:"HUGGINGFACE_API_KEY",openai:"OPENAI_API_KEY",gemini:"GEMINI_API_KEY",deepseek:"DEEPSEEK_API_KEY",xai:"XAI_API_KEY",ollama:"OLLAMA_API_KEY",ollamacloud:"OLLAMA_API_KEY",opencode:"OPENCODE_API_KEY",zen:"OPENCODE_API_KEY"};function T(e,t){let o=r2.cmd("'%"+t).trim();if(!o.includes("=")&&o!=="")return[o.trim(),null,"env"];let i=e.toLowerCase(),r=N;if(O(r)){let l=r2.cmd("'cat "+r),s=re(l);if(i in s)return[s[i],null,"txt"]}let a="~/.r2ai."+i+"-key";if(O(a)){let l=r2.cmd("'cat "+a);return l===""?[null,"Cannot read "+a,"no"]:[l.trim(),null,"file"]}return[null,"Not available","nope"]}function ie(){U(A),D(N),r2.cmd("'ed "+N)}function $(){Object.entries(Oe).forEach(([e,t])=>{let o=T(e,t)[2];console.log(o,"	",e)})}var _e=["DECAI_HEADERS","R2AI_HEADERS"];function Se(e){let t=r2.cmd("'%"+e).trim();return t!==""&&!t.includes("=")?t:""}function ae(e){return e.trim().toLowerCase()}function se(e){let t=e.indexOf(":"),o=e.indexOf("="),i=t!==-1&&(o===-1||t<o)?t:o;if(i===-1)return null;let r=e.slice(0,i).trim();return r===""?null:{name:r,value:e.slice(i+1).trim()}}function le(e){return e.value===""?`${e.name}:`:`${e.name}: ${e.value}`}function J(e){let t=new Map,o=e.replace(/\\n/g,`
`);for(let i of o.split(/\r?\n/g)){let r=i.trim();if(!r||r.startsWith("#"))continue;let a=se(r);a&&t.set(ae(a.name),le(a))}return Array.from(t.values())}function ce(e){return e.join("\\n")}function v(...e){let t=new Map;for(let o of e)for(let i of o){let r=se(i);r&&t.set(ae(r.name),le(r))}return Array.from(t.values())}function Ce(){for(let e of _e){let t=Se(e);if(t)return J(t)}return[]}function ue(){return v(Ce(),n.extraHeaders)}function _(e){return`'${e.replace(/'/g,`'"'"'`)}'`}function Re(e){let{method:t,url:o,headers:i,payload:r}=e,a=["curl","-s"];if(n.timeout>0&&a.push("--max-time",String(n.timeout)),v(["Content-Type: application/json"],i).forEach(s=>a.push("-H",_(s))),t==="POST"){if(!r)throw new Error("Payload required for POST requests");let s=r2.fdump(r);a.push("--data-binary","@-",_(o));let u=a.join(" ")+" < "+_(s)+" && rm "+_(s);return G(u),r2.syscmds(u)}else{a.push(_(o));let s=a.join(" ");return G(s),r2.syscmds(s)}}function de(e){try{let t=Re(e).trim();if(t==="")return{error:"empty response"};try{return JSON.parse(t)}catch{return{error:t,rawOutput:t}}}catch(t){return{error:t.message}}}function w(e,t){return de({method:"GET",url:e,headers:t})}function me(e,t,o){return de({method:"POST",url:e,headers:t,payload:o})}function W(e){return e.split("_")[0].toLowerCase()}function S(e){if(!e.authKey)return;let t=Array.from(new Set([e.keyName,W(e.authKey)].filter(Boolean))),o;for(let i of t){let r=T(i,e.authKey);if(r[0])return r;!o&&r[2]!=="nope"&&(o=r)}return o||T(W(e.authKey),e.authKey)}function pe(e){if(e)return typeof e=="string"?e:e.message}function C(e){return n.baseurl||e.defaultBaseUrl}function R(e,t=ue()){return v(e,t)}function Me(e){return e?["Authorization: Bearer "+e]:[]}function Ne(e){let t=["anthropic-version: 2023-06-01"];return e?v(t,["x-api-key: "+e]):t}function M(e,t){switch(e.authStyle||"none"){case"bearer":return Me(t);case"anthropic":return Ne(t);case"none":default:return[]}}function fe(e,t,o){let i=w(e,t),r=pe(i.error);return r?(console.error(r),"error invalid response"):i.data?.map(o).join(`
`)||""}function Ke(e,t){let o=new Set;return e.filter(i=>{let r=t(i);return o.has(r)?!1:(o.add(r),!0)})}function Ue(e){let t=S(e),o=C(e),i=R(M(e,t?.[0]||null));return fe(o+"/v1/models",i,r=>r.id)}function De(e){let t=S(e),o=C(e),i=R(M(e,t?.[0]||null));return fe(o+"/v1/models",i,r=>r.id)}function Te(e){let t=w(C(e)+"/api/tags",R(M(e,S(e)?.[0]||null))),o=pe(t.error);return o?(console.error(o),"error invalid response"):t.models?.map(i=>i.name).join(`
`)||""}function He(e){let t=S(e),o=w(C(e)+"/v1/models",R(M(e,t?.[0]||null)));return o.data?Ke(o.data,i=>i.name||i.id).map(i=>[Y(i.name||i.id,30),Y(""+(i.max_context_length||""),10),i.description||""].join(" ")).join(`
`):""}var qe={openai:{buildPayload:(e,t)=>({stream:!1,model:e,messages:[{role:"user",content:t}]}),parseResponse:e=>{if(e.error){let t=typeof e.error=="object"?e.error.message:e.error;throw new Error(t||"Unknown error")}if(e.choices&&e.choices[0]?.message?.content)return E(e.choices[0].message.content);throw new Error("Invalid response format")},buildUrl:e=>e+"/v1/chat/completions"},anthropic:{buildPayload:(e,t)=>{let o={model:e,max_tokens:5128,messages:[{role:"user",content:t}]};return n.deterministic&&Object.assign(o,{temperature:0,top_p:0,top_k:1}),o},parseResponse:e=>{if(e.content&&e.content[0]?.text)return E(e.content[0].text);if(e.error){let t=typeof e.error=="object"?e.error.message:e.error;throw new Error(t||"Unknown error")}throw new Error("Invalid response format")},buildUrl:e=>e+"/v1/messages"},ollama:{buildPayload:(e,t)=>{let o={stream:!1,model:e,messages:[{role:"user",content:t}]};return n.deterministic&&(o.options={repeat_last_n:0,top_p:1,top_k:1,temperature:0,repeat_penalty:1,seed:123}),o},parseResponse:e=>{if(e.error){let t=typeof e.error=="string"?e.error:JSON.stringify(e.error);throw new Error(t)}if(e.message?.content)return E(e.message.content);throw new Error(JSON.stringify(e))},buildUrl:e=>e+"/api/chat"},gemini:{buildPayload:(e,t)=>{let o={contents:[{parts:[{text:t}]}]};return n.deterministic&&(o.generationConfig={temperature:0,topP:1,topK:1}),o},parseResponse:e=>{if(e.candidates&&e.candidates[0]?.content?.parts?.[0]?.text)return E(e.candidates[0].content.parts[0].text);throw e.error?new Error(typeof e.error=="string"?e.error:JSON.stringify(e.error)):(console.log(JSON.stringify(e)),new Error("Invalid response format"))},buildUrl:(e,t,o)=>`${e}/v1beta/models/${t}:generateContent?key=${o}`,requiresUrlApiKey:!0}},he={anthropic:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseUrl:"https://api.anthropic.com",authKey:"ANTHROPIC_API_KEY",keyName:"anthropic",authStyle:"anthropic",apiStyle:"anthropic"},claude:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseUrl:"https://api.anthropic.com",authKey:"ANTHROPIC_API_KEY",keyName:"claude",authStyle:"anthropic",apiStyle:"anthropic"},openai:{defaultModel:"gpt-4o-mini",defaultBaseUrl:"https://api.openai.com",authKey:"OPENAI_API_KEY",authStyle:"bearer",apiStyle:"openai"},ollama:{defaultModel:"qwen2.5-coder:latest",defaultBaseUrl:"http://localhost:11434",authStyle:"none",apiStyle:"ollama"},ollamacloud:{defaultModel:"gpt-oss:120b",defaultBaseUrl:"https://ollama.com",authKey:"OLLAMA_API_KEY",keyName:"ollamacloud",authStyle:"bearer",apiStyle:"ollama"},opencode:{defaultModel:"big-pickle",defaultBaseUrl:"https://opencode.ai/zen",authKey:"OPENCODE_API_KEY",keyName:"opencode",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["big-pickle","glm-5","kimi-k2.5"]},zen:{defaultModel:"big-pickle",defaultBaseUrl:"https://opencode.ai/zen",authKey:"OPENCODE_API_KEY",keyName:"zen",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["big-pickle","glm-5","kimi-k2.5"]},gemini:{defaultModel:"gemini-2.5-flash",defaultBaseUrl:"https://generativelanguage.googleapis.com",authKey:"GEMINI_API_KEY",authStyle:"none",apiStyle:"gemini",hardcodedModels:["gemini-2.0-flash","gemini-2.0-flash-lite","gemini-2.5-pro","gemini-2.5-flash","gemini-2.5-flash-lite"]},mistral:{defaultModel:"codestral-latest",defaultBaseUrl:"https://api.mistral.ai",authKey:"MISTRAL_API_KEY",authStyle:"bearer",apiStyle:"openai"},xai:{defaultModel:"grok-beta",defaultBaseUrl:"https://api.x.ai",authKey:"XAI_API_KEY",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["grok-2","grok-beta"]},lmstudio:{defaultModel:"local-model",defaultBaseUrl:"http://127.0.0.1:1234",authStyle:"none",apiStyle:"openai"},deepseek:{defaultModel:"deepseek-coder",defaultBaseUrl:"https://api.deepseek.com",authKey:"DEEPSEEK_API_KEY",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["deepseek-coder","deepseek-chat"]}};function H(e){return he[e]}function z(){return Object.keys(he)}function ge(e){let t=H(e);if(!t)throw new Error(`Unknown provider: ${e}`);if(e==="mistral")return He(t);switch(t.apiStyle){case"openai":return Ue(t);case"anthropic":return De(t);case"ollama":return Te(t);case"gemini":return"";default:return""}}function Fe(e,t){let o=e;return n.think>=0&&(n.think===0?(o+=' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".',o+=" /no_think"):n.think>0&&(o="Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer."+o)),t?o:n.prompt+Le()+o}function Le(){return`
.Translate the code into `+n.language+` programming language
`}function Be(e,t,o,i){let r=n.model||e.defaultModel,a=Fe(o,i),l=S(e);if(t.requiresUrlApiKey&&l?.[1]&&e.authKey)return`Cannot read ~/.r2ai.${W(e.authKey)}-key`;let s=t.buildPayload(r,a),u=R(M(e,l?.[0]||null)),p=t.buildUrl(C(e),r,l?.[0]||void 0);try{return t.parseResponse(me(p,u,JSON.stringify(s)))}catch(m){return"ERROR: "+m.message}}function ye(e,t){let o=H(n.api);return o?Be(o,qe[o.apiStyle],e,t):`Unknown value for 'decai -e api'. Available: ${z().join(", ")}`}function be(e){let t=H(e);if(!t){console.error(`Unknown provider: ${e}`);return}try{let o=ge(e);o&&console.log(o),t.hardcodedModels&&t.hardcodedModels.forEach(i=>console.log(i)),e==="mistral"&&console.log("ministral-8b-latest"),!o&&!t.hardcodedModels&&console.log(t.defaultModel)}catch(o){let i=o;console.error(`Error listing models for ${e}:`,i.message),console.log(t.defaultModel)}}var V=!1;function I(e){return e==="true"||e==="1"}var xe={pipeline:{get:()=>n.pipeline,set:e=>{n.pipeline=e;try{n.decopipe=JSON.parse(r2.cmd("cat "+e))}catch(t){console.error(t)}}},model:{get:()=>n.model,set:e=>{e==="?"?be(n.api):n.model=e.trim()}},deterministic:{get:()=>n.deterministic,set:e=>{n.deterministic=I(e)}},files:{get:()=>n.useFiles,set:e=>{n.useFiles=I(e)}},think:{get:()=>n.think,set:e=>{n.think=e==="true"?1:e==="false"?0:+e}},debug:{get:()=>n.debug,set:e=>{n.debug=I(e)}},timeout:{get:()=>n.timeout,set:e=>{n.timeout=Math.max(0,parseInt(e,10)||0)}},api:{get:()=>n.api,set:e=>{if(e==="?"){let t=z().join(`
`);console.error(t)}else n.api=e}},lang:{get:()=>n.language,set:e=>{n.language=e}},hlang:{get:()=>n.humanLanguage,set:e=>{n.humanLanguage=e}},cache:{get:()=>n.cache,set:e=>{n.cache=I(e)}},cmds:{get:()=>n.commands,set:e=>{n.commands=e}},tts:{get:()=>n.tts,set:e=>{n.tts=I(e)}},yolo:{get:()=>n.yolo,set:e=>{n.yolo=I(e)}},prompt:{get:()=>n.prompt,set:e=>{n.prompt=e}},ctxfile:{get:()=>n.contextFile,set:e=>{n.contextFile=e}},baseurl:{get:()=>n.baseurl,set:e=>{n.baseurl=e}},headers:{get:()=>ce(n.extraHeaders),set:e=>{n.extraHeaders=J(e)}},maxtokens:{get:()=>n.maxInputTokens,set:e=>{n.maxInputTokens=parseInt(e,10)||-1}}};function Ye(){n.decopipe={...c.decopipe},n.baseurl=c.baseurl,n.extraHeaders=[...c.extraHeaders],n.api=c.api,n.pipeline=c.pipeline,n.commands=c.commands,n.yolo=c.yolo,n.tts=c.tts,n.language=c.language,n.humanLanguage=c.humanLanguage,n.deterministic=c.deterministic,n.debug=c.debug,n.timeout=c.timeout,n.think=c.think,n.useFiles=c.useFiles,n.contextFile=c.contextFile,n.model=c.model,n.cache=c.cache,n.maxInputTokens=c.maxInputTokens,n.prompt=c.prompt}function je(e){let t=e.trim();return!t||t.startsWith("#")?null:t.startsWith("decai -e ")?t.slice(9).trim():t}function x(e){let t=e.indexOf("="),o=t===-1?e:e.slice(0,t),i=t===-1?void 0:e.slice(t+1),r=xe[o];if(!r){console.error("Unknown config key");return}typeof i<"u"?r.set(i):console.log(r.get())}function ke(){Object.entries(xe).forEach(([e,t])=>{let o=t.get();console.log("decai -e "+e+"="+o)})}function Ee(){if(Ye(),!O(P))return;let e=r2.cmd("'cat "+P);for(let t of e.split(/\r?\n/)){let o=je(t);o&&x(o)}}function Ae(){V||(Ee(),V=!0)}function ve(){U(A),D(P),r2.cmd("'ed "+P),Ee(),V=!0}function h(e,t,o=!1){let i=(t||"").replace(/`/g,""),r=e.replace(/'/g,"");if(n.api==="r2"||n.api==="r2ai"){let l=Z(".pdc.txt");ne(l,i);let s=r.startsWith("-")?r:["-i",l,r].join(" "),p=(n.baseurl?n.baseurl+"/cmd":n.host+":"+n.port+"/cmd")+"/"+encodeURIComponent(s),m=w(p,[]);return m.error?`Error: ${m.error}`:m.result||JSON.stringify(m)||"Cannot curl, use r2ai-server or r2ai -w"}if(r.startsWith("-"))return"";let a=r+`:
`+i;return n.maxInputTokens>0&&a.length>n.maxInputTokens&&(a=a.slice(0,n.maxInputTokens)),ye(a,o)}function we(){let e="",t=o=>e+=" "+b+" "+o+`
`;e+="Usage: "+b+` (-h) ...
`,e+="Version: "+X+`
`,t("-a [query]    - solve query with auto mode"),t("-b [url]      - set base URL (alias for decai -e baseurl)"),t("-d [f1 ..]    - decompile given functions"),t("-dd [..]      - same as above, but ignoring cache"),t("-dD [query]   - decompile current function with given extra query"),t("-dr           - decompile function and its called ones (recursive)"),t("-e            - display and change eval config vars"),t("-E            - edit decai.txt"),t("-h            - show this help"),t("-H            - help setting up r2ai"),t("-i [f] [q]    - include given file and query"),t("-k            - list API key status"),t("-K            - edit apikeys.txt"),t("-m [model]    - use -m? or -e model=? to list the available models"),t("-n            - suggest better function name"),t("-p [provider] - same as decai -e api (will be provider)"),t("-q [text]     - query language model with given text"),t("-Q [text]     - query on top of the last output"),t("-r [prompt]   - change role prompt (same as: decai -e prompt)"),t("-R            - reset role prompt to default prompt"),t("-s            - function signature"),t("-v            - show local variables"),t("-V            - find vulnerabilities"),t("-x[*]         - eXplain current function (-x* for r2 script)"),r2.log(e.trim())}function q(e,t,o,i){if(o){let s=r2.cmd("anos").trim();if(s.length>0)return s}let r="";if(i){let s=r2.cmd("s");r+=`## Context functions:
`;let u=r2.cmdAt("axff~^C[2]~$$",s);for(let p of u.split(/\n/g))r+=r2.cmd("pdc@"+p);r2.cmd("s "+s)}let a=t?" "+e:"",l=r2.cmd("e scr.color");try{let s=e.slice(2).trim(),u=0,p="";n.contextFile!==""&&r2.cmd2("test -f "+n.contextFile).value===0&&(p+=`## Context:
[START]
`+r2.cmd("cat "+n.contextFile)+`
[END]
`),r2.cmd("e scr.color=0");let m=`## Before:
`;for(let f of n.commands.split(",")){if(f.trim()==="")continue;let F=t||s.trim().length===0?f:f+"@@= "+s,k=r2.cmd(F);k.length>5&&(m+="Output of "+f+`:
[START]
`+k+`
[END]
`,u++)}if(m+=`## After:
`,r2.cmd("e scr.color="+l),u===0){console.error("Nothing to do.");return}let d="";if(n.decopipe.use){let f=n.decopipe[n.decopipe.default],F=n.model,k=p+m;for(let L of f.pipeline){L.model&&(n.model=L.model);let Q=L.query+". "+f.globalQuery;d=h(Q,k,!0),n.debug&&console.log(`QUERY
`,Q,`
INPUT
`,k,`
OUTPUT
`,d),k=d}d=k,n.model=F}else{let f=a;p+=m+r,d=h(f,p,!1),n.lastOutput=d}return o&&d.length>1&&r2.call("ano=base64:"+j(d)),d.startsWith("```")&&(d=d.replace(/```.*\n/,"").replace(/```$/,"")),d.trim()}catch(s){r2.cmd("e scr.color="+l);let u=s;console.error(u,u.stack);return}}function Ge(){let e=r2.cmd("e scr.color");r2.cmd("e scr.color=0");let t="[START]"+n.commands.split(",").map(r=>r2.cmd(r)).join(`
`)+"[END]";r2.cmd("e scr.color="+e);let i=h("Analyze function calls, references, comments and strings, loops and ignore registers and memory accesses. Explain the purpose of this function in a single short sentence. /no_think Do not introduce or argue the response, translation of the explanation in "+n.humanLanguage,t,!0).trim().split(/\n/g);return i[i.length-1].trim()}function $e(){let e=n.language,t=r2.cmd("afv;pdc");n.language="C";let o="'afs "+h("analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the return. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",t,!1),i=o.indexOf("{");return i!==-1&&(o=o.substring(0,i)),n.language=e,o}function Je(e,t){let o=[];for(;;){let i=B.auto;if(o.length>0){i+=`## Command Results

`;for(let a of o){let l=JSON.parse(a);i+="### "+l.command+"\n\n```\n"+l.response+"\n```\n"}}i+=`

## User Prompt

`+e,n.debug&&console.log(`#### input
`,i,`
#### /input`),console.log("Thinking...");let r=h("",i,!0);n.debug&&console.log(`#### output
`,r,`
#### /output`);try{let a=JSON.parse(oe(te(E(r))));if(a.action==="r2cmd"||a.action==="response"||a.action===a.command){let l=a.command||"";a.reason&&(console.log("[r2cmd] Reasoning: "+a.reason),n.tts&&(r2.syscmd("pkill say"),r2.syscmd("say -v Alex -r 250 '"+a.reason.replace(/'/g,"")+"' &"))),console.log("[r2cmd] Action: "+a.description),console.log("[r2cmd] Command: "+l);let s=l;n.yolo||(s=We(l,t)),console.log("[r2cmd] Running: "+s);let u=r2.cmd2(s),p=u.logs?u.logs.map(f=>f.type+": "+f.message).join(`
`):"",m=(u.res+p).trim();console.log(m);let d=ee(m);n.debug&&console.log(`<r2output>
`,d,`
<(r2output>`),o.push(JSON.stringify({action:"response",command:s,description:a.description,response:d}))}else if(a.action==="reply"){console.log(`Done
`,a.response);break}else console.log(`Unknown response
`,JSON.stringify(r))}catch(a){let l=r.indexOf('response": "');if(l!==-1){let s=r.slice(l+12).replace(/\\n/g,`
`).replace(/\\/g,"");console.log(s)}else console.log(r),console.error(a);break}}}function We(e,t){for(;;){let o=r2.cmd("'?ie Tweak command? ('?' for help)").trim();if(o==="q!"){console.error("Break!");break}if(o==="?"){ze();continue}else if(o.startsWith(":")){console.log(r2.cmd(o.slice(1)));continue}else if(o.startsWith("-e")){t(o);continue}else{if(o==="!")return"?e do NOT execute '"+e+"' again, continue without it";if(o.startsWith("!")){console.log(r2.syscmd(o.slice(1)));continue}else{if(o==="q")return"?e All data collected!. Do not call more commands, reply the solutions";if(o){let i=o.indexOf("#");return i!==-1?o.slice(0,i).trim():o}else return e}}}return e}function ze(){console.log(" '!'     do not run this command"),console.log(" '!c'    run system command"),console.log(" 'q'     to quit auto and try to solve"),console.log(" 'q!'    quit auto without solving"),console.log(" 'c # C' use given command with comment"),console.log(" ':c'    run r2 command without feeding auto"),console.log(" '-e'    set decai configuration variables")}function Ve(e){return e.slice(2).trim()}function Ie(e,t){if(e===""||!e.startsWith("-")){we();return}let o="",i=e[1],r=Ve(e);switch(i){case"H":console.log(B.decai);break;case"a":Je(r,t);break;case"m":{r==="="?x("model="):r?x("model="+r):x("model");break}case"n":case"f":{o=r2.cmd("axff~$[3]");let a=r2.cmd("fd.").trim().split(/\n/).filter(l=>!l.startsWith("secti")).join(",");o=h("give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: "+a,o,!1).trim(),o+=" @ "+r2.cmd("?v $FB").trim();break}case"v":o=r2.cmd("afv;pdc"),o=h("guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",o,!1);break;case"i":{let a=r.split(/\s+/).filter(Boolean);if(a.length>=2){let l=a[0],s=a.slice(1).join(" "),u=r2.cmd("cat "+l);console.log(h(s,u,!0))}else console.log("Use: decai -i [file] [query ...]");break}case"p":{r?x("api="+r):$();break}case"r":{r?n.prompt=r:console.log(n.prompt);break}case"R":n.prompt=K;break;case"s":o=$e();break;case"V":o=h("find vulnerabilities, dont show the code, only show the response, provide a sample exploit",n.lastOutput,!1);break;case"K":ie();break;case"E":ve();break;case"k":$();break;case"b":{r?x("baseurl="+r):console.log(n.baseurl);break}case"e":{r?x(r):ke();break}case"q":try{o=h(r,null,!0)}catch(a){let l=a;console.error(l,l.stack)}break;case"Q":o=h(r,n.lastOutput,!1);break;case"x":o=Ge(),(e[2]==="*"||e[2]==="r")&&(o="'CC "+o);break;case"d":e[2]==="r"?o=q(e.slice(2),!0,n.cache,!0)||"":e[2]==="d"?o=q(e,!1,!1,!1)||"":e[2]==="D"?o=q(e,!0,!1,!1)||"":o=q(e,!1,n.cache,!1)||"";break;default:we();break}return o||void 0}function Pe(e){Ae();let t=Ie(e,Pe);return t&&r2.log(t),!0}function Qe(){r2.unload("core",b),r2.plugin("core",function(){function e(t){if(t.startsWith(b)){let o=t.slice(b.length).trim();return Pe(o)}return!1}return{name:b,license:"MIT",desc:"r2 decompiler based on r2ai",call:e}})}Qe();
