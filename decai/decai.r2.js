📦
26116 /main.js
✄
var Q="1.3.2",y="decai",A="~/.config/r2ai",N=A+"/apikeys.txt",I=A+"/decai.txt",K="Rewrite this pseudocode into concise and clean code. Output only the provided function. Do not add wrappers, helper examples, test code, or main-like functions. Replace goto with structured control flow, simplify as much as possible, infer types and use better names for variables and parameters, some strings may be appearing as comments, preserve only what is implied by the input, and remove dead code.",F={decai:`# Using Decai

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
`};var k={decopipe:{use:!1},host:"http://localhost",port:"11434",baseurl:"",extraHeaders:[],api:"ollama",pipeline:"",commands:"pdc",yolo:!1,tts:!1,language:"C",humanLanguage:"English",deterministic:!0,debug:!1,timeout:180,think:-1,useFiles:!1,contextFile:"",model:"",cache:!1,maxInputTokens:-1,prompt:K,lastOutput:""},n={...k,decopipe:{...k.decopipe},extraHeaders:[...k.extraHeaders]};function X(e){return(r2.cmd("-e dir.tmp").trim()??".")+"/"+e}function U(e,t){r2.cmd("'mkdir -p "+e),r2.cmd("'touch "+t)}function O(e){return(r2.cmd2("test -h").logs?.[0]?.message??"").includes("-fdx")?!0:r2.cmd("'test -vf "+e).startsWith("found")}function B(e,t){return e+" ".repeat(Math.max(0,t-e.length))}function Z(e){return e.replace(/\x1b\[[0-9;]*m/g,"")}function ee(e){let t=e.match(/```json\s*([\s\S]*?)```/);return t&&t[1]?t[1].trim():e}function te(e){let t=e,o=t.indexOf("{");o!==-1&&(t=t.slice(o));let i=t.lastIndexOf("}");return i!==-1&&(t=t.slice(0,i+1)),t}function j(e){return btoa(e)}function oe(e,t){let o=j(t);r2.cmd("p6ds "+o+" > "+e)}function E(e){let t=e;return n.think!==2&&(t=t.replace(/<think>[\s\S]*?<\/think>/gi,"")),t.split(`
`).filter(o=>!o.trim().startsWith("```")).join(`
`)}function Y(e){n.debug&&console.log(e)}function ne(e){let t={};for(let o of e.split(/\r?\n/)){let i=o.trim();if(!i||i.startsWith("#"))continue;let[r,...s]=i.split("=");if(!r||s.length===0)continue;let l=s.join("=").trim(),a=r.toLowerCase().replace(/_api_key$/i,"");t[a]=l}return t}var Ie={mistral:"MISTRAL_API_KEY",anthropic:"ANTHROPIC_API_KEY",huggingface:"HUGGINGFACE_API_KEY",openai:"OPENAI_API_KEY",gemini:"GEMINI_API_KEY",deepseek:"DEEPSEEK_API_KEY",xai:"XAI_API_KEY",ollama:"OLLAMA_API_KEY",ollamacloud:"OLLAMA_API_KEY",opencode:"OPENCODE_API_KEY",zen:"OPENCODE_API_KEY"};function T(e,t){let o=r2.cmd("'%"+t).trim();if(!o.includes("=")&&o!=="")return[o.trim(),null,"env"];let i=e.toLowerCase(),r=N;if(O(r)){let l=r2.cmd("'cat "+r),a=ne(l);if(i in a)return[a[i],null,"txt"]}let s="~/.r2ai."+i+"-key";if(O(s)){let l=r2.cmd("'cat "+s);return l===""?[null,"Cannot read "+s,"no"]:[l.trim(),null,"file"]}return[null,"Not available","nope"]}function re(){U(A,N),r2.cmd("'ed "+N)}function G(){Object.entries(Ie).forEach(([e,t])=>{let o=T(e,t)[2];console.log(o,"	",e)})}var Oe=["DECAI_HEADERS","R2AI_HEADERS"];function _e(e){let t=r2.cmd("'%"+e).trim();return t!==""&&!t.includes("=")?t:""}function ie(e){return e.trim().toLowerCase()}function se(e){let t=e.indexOf(":"),o=e.indexOf("="),i=t!==-1&&(o===-1||t<o)?t:o;if(i===-1)return null;let r=e.slice(0,i).trim();return r===""?null:{name:r,value:e.slice(i+1).trim()}}function ae(e){return e.value===""?`${e.name}:`:`${e.name}: ${e.value}`}function $(e){let t=new Map,o=e.replace(/\\n/g,`
`);for(let i of o.split(/\r?\n/g)){let r=i.trim();if(!r||r.startsWith("#"))continue;let s=se(r);s&&t.set(ie(s.name),ae(s))}return Array.from(t.values())}function le(e){return e.join("\\n")}function v(...e){let t=new Map;for(let o of e)for(let i of o){let r=se(i);r&&t.set(ie(r.name),ae(r))}return Array.from(t.values())}function Se(){for(let e of Oe){let t=_e(e);if(t)return $(t)}return[]}function ce(){return v(Se(),n.extraHeaders)}function _(e){return`'${e.replace(/'/g,`'"'"'`)}'`}function Ce(e){let{method:t,url:o,headers:i,payload:r}=e,s=["curl","-s"];if(n.timeout>0&&s.push("--max-time",String(n.timeout)),v(["Content-Type: application/json"],i).forEach(a=>s.push("-H",_(a))),t==="POST"){if(!r)throw new Error("Payload required for POST requests");let a=r2.fdump(r);s.push("--data-binary","@-",_(o));let c=s.join(" ")+" < "+_(a)+" && rm "+_(a);return Y(c),r2.syscmds(c)}else{s.push(_(o));let a=s.join(" ");return Y(a),r2.syscmds(a)}}function ue(e){try{let t=Ce(e).trim();if(t==="")return{error:"empty response"};try{return JSON.parse(t)}catch{return{error:t,rawOutput:t}}}catch(t){return{error:t.message}}}function w(e,t){return ue({method:"GET",url:e,headers:t})}function de(e,t,o){return ue({method:"POST",url:e,headers:t,payload:o})}function J(e){return e.split("_")[0].toLowerCase()}function S(e){if(!e.authKey)return;let t=Array.from(new Set([e.keyName,J(e.authKey)].filter(Boolean))),o;for(let i of t){let r=T(i,e.authKey);if(r[0])return r;!o&&r[2]!=="nope"&&(o=r)}return o||T(J(e.authKey),e.authKey)}function me(e){if(e)return typeof e=="string"?e:e.message}function C(e){return n.baseurl||e.defaultBaseUrl}function R(e,t=ce()){return v(e,t)}function Re(e){return e?["Authorization: Bearer "+e]:[]}function Me(e){let t=["anthropic-version: 2023-06-01"];return e?v(t,["x-api-key: "+e]):t}function M(e,t){switch(e.authStyle||"none"){case"bearer":return Re(t);case"anthropic":return Me(t);case"none":default:return[]}}function pe(e,t,o){let i=w(e,t),r=me(i.error);return r?(console.error(r),"error invalid response"):i.data?.map(o).join(`
`)||""}function Ne(e,t){let o=new Set;return e.filter(i=>{let r=t(i);return o.has(r)?!1:(o.add(r),!0)})}function Ke(e){let t=S(e),o=C(e),i=R(M(e,t?.[0]||null));return pe(o+"/v1/models",i,r=>r.id)}function Ue(e){let t=S(e),o=C(e),i=R(M(e,t?.[0]||null));return pe(o+"/v1/models",i,r=>r.id)}function Te(e){let t=w(C(e)+"/api/tags",R(M(e,S(e)?.[0]||null))),o=me(t.error);return o?(console.error(o),"error invalid response"):t.models?.map(i=>i.name).join(`
`)||""}function De(e){let t=S(e),o=w(C(e)+"/v1/models",R(M(e,t?.[0]||null)));return o.data?Ne(o.data,i=>i.name||i.id).map(i=>[B(i.name||i.id,30),B(""+(i.max_context_length||""),10),i.description||""].join(" ")).join(`
`):""}var He={openai:{buildPayload:(e,t)=>({stream:!1,model:e,messages:[{role:"user",content:t}]}),parseResponse:e=>{if(e.error){let t=typeof e.error=="object"?e.error.message:e.error;throw new Error(t||"Unknown error")}if(e.choices&&e.choices[0]?.message?.content)return E(e.choices[0].message.content);throw new Error("Invalid response format")},buildUrl:e=>e+"/v1/chat/completions"},anthropic:{buildPayload:(e,t)=>{let o={model:e,max_tokens:5128,messages:[{role:"user",content:t}]};return n.deterministic&&Object.assign(o,{temperature:0,top_p:0,top_k:1}),o},parseResponse:e=>{if(e.content&&e.content[0]?.text)return E(e.content[0].text);if(e.error){let t=typeof e.error=="object"?e.error.message:e.error;throw new Error(t||"Unknown error")}throw new Error("Invalid response format")},buildUrl:e=>e+"/v1/messages"},ollama:{buildPayload:(e,t)=>{let o={stream:!1,model:e,messages:[{role:"user",content:t}]};return n.deterministic&&(o.options={repeat_last_n:0,top_p:1,top_k:1,temperature:0,repeat_penalty:1,seed:123}),o},parseResponse:e=>{if(e.error){let t=typeof e.error=="string"?e.error:JSON.stringify(e.error);throw new Error(t)}if(e.message?.content)return E(e.message.content);throw new Error(JSON.stringify(e))},buildUrl:e=>e+"/api/chat"},gemini:{buildPayload:(e,t)=>{let o={contents:[{parts:[{text:t}]}]};return n.deterministic&&(o.generationConfig={temperature:0,topP:1,topK:1}),o},parseResponse:e=>{if(e.candidates&&e.candidates[0]?.content?.parts?.[0]?.text)return E(e.candidates[0].content.parts[0].text);throw e.error?new Error(typeof e.error=="string"?e.error:JSON.stringify(e.error)):(console.log(JSON.stringify(e)),new Error("Invalid response format"))},buildUrl:(e,t,o)=>`${e}/v1beta/models/${t}:generateContent?key=${o}`,requiresUrlApiKey:!0}},fe={anthropic:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseUrl:"https://api.anthropic.com",authKey:"ANTHROPIC_API_KEY",keyName:"anthropic",authStyle:"anthropic",apiStyle:"anthropic"},claude:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseUrl:"https://api.anthropic.com",authKey:"ANTHROPIC_API_KEY",keyName:"claude",authStyle:"anthropic",apiStyle:"anthropic"},openai:{defaultModel:"gpt-4o-mini",defaultBaseUrl:"https://api.openai.com",authKey:"OPENAI_API_KEY",authStyle:"bearer",apiStyle:"openai"},ollama:{defaultModel:"qwen2.5-coder:latest",defaultBaseUrl:"http://localhost:11434",authStyle:"none",apiStyle:"ollama"},ollamacloud:{defaultModel:"gpt-oss:120b",defaultBaseUrl:"https://ollama.com",authKey:"OLLAMA_API_KEY",keyName:"ollamacloud",authStyle:"bearer",apiStyle:"ollama"},opencode:{defaultModel:"big-pickle",defaultBaseUrl:"https://opencode.ai/zen",authKey:"OPENCODE_API_KEY",keyName:"opencode",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["big-pickle","glm-5","kimi-k2.5"]},zen:{defaultModel:"big-pickle",defaultBaseUrl:"https://opencode.ai/zen",authKey:"OPENCODE_API_KEY",keyName:"zen",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["big-pickle","glm-5","kimi-k2.5"]},gemini:{defaultModel:"gemini-2.5-flash",defaultBaseUrl:"https://generativelanguage.googleapis.com",authKey:"GEMINI_API_KEY",authStyle:"none",apiStyle:"gemini",hardcodedModels:["gemini-2.0-flash","gemini-2.0-flash-lite","gemini-2.5-pro","gemini-2.5-flash","gemini-2.5-flash-lite"]},mistral:{defaultModel:"codestral-latest",defaultBaseUrl:"https://api.mistral.ai",authKey:"MISTRAL_API_KEY",authStyle:"bearer",apiStyle:"openai"},xai:{defaultModel:"grok-beta",defaultBaseUrl:"https://api.x.ai",authKey:"XAI_API_KEY",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["grok-2","grok-beta"]},lmstudio:{defaultModel:"local-model",defaultBaseUrl:"http://127.0.0.1:1234",authStyle:"none",apiStyle:"openai"},deepseek:{defaultModel:"deepseek-coder",defaultBaseUrl:"https://api.deepseek.com",authKey:"DEEPSEEK_API_KEY",authStyle:"bearer",apiStyle:"openai",hardcodedModels:["deepseek-coder","deepseek-chat"]}};function D(e){return fe[e]}function W(){return Object.keys(fe)}function he(e){let t=D(e);if(!t)throw new Error(`Unknown provider: ${e}`);if(e==="mistral")return De(t);switch(t.apiStyle){case"openai":return Ke(t);case"anthropic":return Ue(t);case"ollama":return Te(t);case"gemini":return"";default:return""}}function qe(e,t){let o=e;return n.think>=0&&(n.think===0?(o+=' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".',o+=" /no_think"):n.think>0&&(o="Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer."+o)),t?o:n.prompt+Le()+o}function Le(){return`
.Translate the code into `+n.language+` programming language
`}function Fe(e,t,o,i){let r=n.model||e.defaultModel,s=qe(o,i),l=S(e);if(t.requiresUrlApiKey&&l?.[1]&&e.authKey)return`Cannot read ~/.r2ai.${J(e.authKey)}-key`;let a=t.buildPayload(r,s),c=R(M(e,l?.[0]||null)),m=t.buildUrl(C(e),r,l?.[0]||void 0);try{return t.parseResponse(de(m,c,JSON.stringify(a)))}catch(d){return"ERROR: "+d.message}}function ge(e,t){let o=D(n.api);return o?Fe(o,He[o.apiStyle],e,t):`Unknown value for 'decai -e api'. Available: ${W().join(", ")}`}function ye(e){let t=D(e);if(!t){console.error(`Unknown provider: ${e}`);return}try{let o=he(e);o&&console.log(o),t.hardcodedModels&&t.hardcodedModels.forEach(i=>console.log(i)),e==="mistral"&&console.log("ministral-8b-latest"),!o&&!t.hardcodedModels&&console.log(t.defaultModel)}catch(o){let i=o;console.error(`Error listing models for ${e}:`,i.message),console.log(t.defaultModel)}}var z=!1;function P(e){return e==="true"||e==="1"}var be={pipeline:{get:()=>n.pipeline,set:e=>{n.pipeline=e;try{n.decopipe=JSON.parse(r2.cmd("cat "+e))}catch(t){console.error(t)}}},model:{get:()=>n.model,set:e=>{e==="?"?ye(n.api):n.model=e.trim()}},deterministic:{get:()=>n.deterministic,set:e=>{n.deterministic=P(e)}},files:{get:()=>n.useFiles,set:e=>{n.useFiles=P(e)}},think:{get:()=>n.think,set:e=>{n.think=e==="true"?1:e==="false"?0:+e}},debug:{get:()=>n.debug,set:e=>{n.debug=P(e)}},timeout:{get:()=>n.timeout,set:e=>{n.timeout=Math.max(0,parseInt(e,10)||0)}},api:{get:()=>n.api,set:e=>{if(e==="?"){let t=W().join(`
`);console.error(t)}else n.api=e}},lang:{get:()=>n.language,set:e=>{n.language=e}},hlang:{get:()=>n.humanLanguage,set:e=>{n.humanLanguage=e}},cache:{get:()=>n.cache,set:e=>{n.cache=P(e)}},cmds:{get:()=>n.commands,set:e=>{n.commands=e}},tts:{get:()=>n.tts,set:e=>{n.tts=P(e)}},yolo:{get:()=>n.yolo,set:e=>{n.yolo=P(e)}},prompt:{get:()=>n.prompt,set:e=>{n.prompt=e}},ctxfile:{get:()=>n.contextFile,set:e=>{n.contextFile=e}},baseurl:{get:()=>n.baseurl,set:e=>{n.baseurl=e}},headers:{get:()=>le(n.extraHeaders),set:e=>{n.extraHeaders=$(e)}},maxtokens:{get:()=>n.maxInputTokens,set:e=>{n.maxInputTokens=parseInt(e,10)||-1}}};function Be(){let e={host:n.host,port:n.port,lastOutput:n.lastOutput};Object.assign(n,k,e),n.decopipe={...k.decopipe},n.extraHeaders=[...k.extraHeaders]}function je(e){let t=e.trim();return!t||t.startsWith("#")?null:t.startsWith("decai -e ")?t.slice(9).trim():t}function b(e){let t=e.indexOf("="),o=t===-1?e:e.slice(0,t),i=t===-1?void 0:e.slice(t+1),r=be[o];if(!r){console.error("Unknown config key");return}typeof i<"u"?r.set(i):console.log(r.get())}function xe(){Object.entries(be).forEach(([e,t])=>{let o=t.get();console.log("decai -e "+e+"="+o)})}function ke(){if(Be(),!O(I))return;let e=r2.cmd("'cat "+I);for(let t of e.split(/\r?\n/)){let o=je(t);o&&b(o)}}function Ee(){z||(ke(),z=!0)}function Ae(){U(A,I),r2.cmd("'ed "+I),ke(),z=!0}function f(e,t,o=!1){let i=(t||"").replace(/`/g,""),r=e.replace(/'/g,"");if(n.api==="r2"||n.api==="r2ai"){let l=X(".pdc.txt");oe(l,i);let a=r.startsWith("-")?r:["-i",l,r].join(" "),m=(n.baseurl?n.baseurl+"/cmd":n.host+":"+n.port+"/cmd")+"/"+encodeURIComponent(a),d=w(m,[]);return d.error?`Error: ${d.error}`:d.result||JSON.stringify(d)||"Cannot curl, use r2ai-server or r2ai -w"}if(r.startsWith("-"))return"";let s=r+`:
`+i;return n.maxInputTokens>0&&s.length>n.maxInputTokens&&(s=s.slice(0,n.maxInputTokens)),ge(s,o)}function ve(){let e="",t=o=>e+=" "+y+" "+o+`
`;e+="Usage: "+y+` (-h) ...
`,e+="Version: "+Q+`
`,t("-a [query]    - solve query with auto mode"),t("-b [url]      - set base URL (alias for decai -e baseurl)"),t("-d [f1 ..]    - decompile given functions"),t("-dd [..]      - same as above, but ignoring cache"),t("-dD [query]   - decompile current function with given extra query"),t("-dr           - decompile function and its called ones (recursive)"),t("-e            - display and change eval config vars"),t("-E            - edit decai.txt"),t("-h            - show this help"),t("-H            - help setting up r2ai"),t("-i [f] [q]    - include given file and query"),t("-k            - list API key status"),t("-K            - edit apikeys.txt"),t("-m [model]    - use -m? or -e model=? to list the available models"),t("-n            - suggest better function name"),t("-p [provider] - same as decai -e api (will be provider)"),t("-q [text]     - query language model with given text"),t("-Q [text]     - query on top of the last output"),t("-r [prompt]   - change role prompt (same as: decai -e prompt)"),t("-R            - reset role prompt to default prompt"),t("-s            - function signature"),t("-v            - show local variables"),t("-V            - find vulnerabilities"),t("-x[*]         - eXplain current function (-x* for r2 script)"),r2.log(e.trim())}function H(e,t,o,i){if(o){let a=r2.cmd("anos").trim();if(a.length>0)return a}let r="";if(i){let a=r2.cmd("s");r+=`## Context functions:
`;let c=r2.cmdAt("axff~^C[2]~$$",a);for(let m of c.split(/\n/g))r+=r2.cmd("pdc@"+m);r2.cmd("s "+a)}let s=t?" "+e:"",l=r2.cmd("e scr.color");try{let a=e.slice(2).trim(),c=0,m="";n.contextFile!==""&&r2.cmd2("test -f "+n.contextFile).value===0&&(m+=`## Context:
[START]
`+r2.cmd("cat "+n.contextFile)+`
[END]
`),r2.cmd("e scr.color=0");let d=`## Before:
`;for(let p of n.commands.split(",")){if(p.trim()==="")continue;let q=t||a.trim().length===0?p:p+"@@= "+a,x=r2.cmd(q);x.length>5&&(d+="Output of "+p+`:
[START]
`+x+`
[END]
`,c++)}if(d+=`## After:
`,r2.cmd("e scr.color="+l),c===0){console.error("Nothing to do.");return}let u="";if(n.decopipe.use){let p=n.decopipe[n.decopipe.default],q=n.model,x=m+d;for(let L of p.pipeline){L.model&&(n.model=L.model);let V=L.query+". "+p.globalQuery;u=f(V,x,!0),n.debug&&console.log(`QUERY
`,V,`
INPUT
`,x,`
OUTPUT
`,u),x=u}u=x,n.model=q}else{let p=s;m+=d+r,u=f(p,m,!1),n.lastOutput=u}return o&&u.length>1&&r2.call("ano=base64:"+j(u)),u.startsWith("```")&&(u=u.replace(/```.*\n/,"").replace(/```$/,"")),u.trim()}catch(a){r2.cmd("e scr.color="+l);let c=a;console.error(c,c.stack);return}}function Ye(){let e=r2.cmd("e scr.color");r2.cmd("e scr.color=0");let t="[START]"+n.commands.split(",").map(r=>r2.cmd(r)).join(`
`)+"[END]";r2.cmd("e scr.color="+e);let i=f("Analyze function calls, references, comments and strings, loops and ignore registers and memory accesses. Explain the purpose of this function in a single short sentence. /no_think Do not introduce or argue the response, translation of the explanation in "+n.humanLanguage,t,!0).trim().split(/\n/g);return i[i.length-1].trim()}function Ge(){let e=n.language,t=r2.cmd("afv;pdc");n.language="C";let o="'afs "+f("analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the return. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",t,!1),i=o.indexOf("{");return i!==-1&&(o=o.substring(0,i)),n.language=e,o}function $e(e,t){let o=[];for(;;){let i=F.auto;if(o.length>0){i+=`## Command Results

`;for(let s of o){let l=JSON.parse(s);i+="### "+l.command+"\n\n```\n"+l.response+"\n```\n"}}i+=`

## User Prompt

`+e,n.debug&&console.log(`#### input
`,i,`
#### /input`),console.log("Thinking...");let r=f("",i,!0);n.debug&&console.log(`#### output
`,r,`
#### /output`);try{let s=JSON.parse(te(ee(E(r))));if(s.action==="r2cmd"||s.action==="response"||s.action===s.command){let l=s.command||"";s.reason&&(console.log("[r2cmd] Reasoning: "+s.reason),n.tts&&(r2.syscmd("pkill say"),r2.syscmd("say -v Alex -r 250 '"+s.reason.replace(/'/g,"")+"' &"))),console.log("[r2cmd] Action: "+s.description),console.log("[r2cmd] Command: "+l);let a=l;n.yolo||(a=Je(l,t)),console.log("[r2cmd] Running: "+a);let c=r2.cmd2(a),m=c.logs?c.logs.map(p=>p.type+": "+p.message).join(`
`):"",d=(c.res+m).trim();console.log(d);let u=Z(d);n.debug&&console.log(`<r2output>
`,u,`
<(r2output>`),o.push(JSON.stringify({action:"response",command:a,description:s.description,response:u}))}else if(s.action==="reply"){console.log(`Done
`,s.response);break}else console.log(`Unknown response
`,JSON.stringify(r))}catch(s){let l=r.indexOf('response": "');if(l!==-1){let a=r.slice(l+12).replace(/\\n/g,`
`).replace(/\\/g,"");console.log(a)}else console.log(r),console.error(s);break}}}function Je(e,t){for(;;){let o=r2.cmd("'?ie Tweak command? ('?' for help)").trim();if(o==="q!"){console.error("Break!");break}if(o==="?"){We();continue}else if(o.startsWith(":")){console.log(r2.cmd(o.slice(1)));continue}else if(o.startsWith("-e")){t(o);continue}else{if(o==="!")return"?e do NOT execute '"+e+"' again, continue without it";if(o.startsWith("!")){console.log(r2.syscmd(o.slice(1)));continue}else{if(o==="q")return"?e All data collected!. Do not call more commands, reply the solutions";if(o){let i=o.indexOf("#");return i!==-1?o.slice(0,i).trim():o}else return e}}}return e}function We(){console.log(" '!'     do not run this command"),console.log(" '!c'    run system command"),console.log(" 'q'     to quit auto and try to solve"),console.log(" 'q!'    quit auto without solving"),console.log(" 'c # C' use given command with comment"),console.log(" ':c'    run r2 command without feeding auto"),console.log(" '-e'    set decai configuration variables")}function ze(e){return e.slice(2).trim()}function we(e,t){if(e===""||!e.startsWith("-")){ve();return}let o="",i=e[1],r=ze(e);switch(i){case"H":console.log(F.decai);break;case"a":$e(r,t);break;case"m":{r==="="?b("model="):r?b("model="+r):b("model");break}case"n":case"f":{o=r2.cmd("axff~$[3]");let s=r2.cmd("fd.").trim().split(/\n/).filter(l=>!l.startsWith("secti")).join(",");o=f("give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: "+s,o,!1).trim(),o+=" @ "+r2.cmd("?v $FB").trim();break}case"v":o=r2.cmd("afv;pdc"),o=f("guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",o,!1);break;case"i":{let s=r.split(/\s+/).filter(Boolean);if(s.length>=2){let l=s[0],a=s.slice(1).join(" "),c=r2.cmd("cat "+l);console.log(f(a,c,!0))}else console.log("Use: decai -i [file] [query ...]");break}case"p":{r?b("api="+r):G();break}case"r":{r?n.prompt=r:console.log(n.prompt);break}case"R":n.prompt=K;break;case"s":o=Ge();break;case"V":o=f("find vulnerabilities, dont show the code, only show the response, provide a sample exploit",n.lastOutput,!1);break;case"K":re();break;case"E":Ae();break;case"k":G();break;case"b":{r?b("baseurl="+r):console.log(n.baseurl);break}case"e":{r?b(r):xe();break}case"q":try{o=f(r,null,!0)}catch(s){let l=s;console.error(l,l.stack)}break;case"Q":o=f(r,n.lastOutput,!1);break;case"x":o=Ye(),(e[2]==="*"||e[2]==="r")&&(o="'CC "+o);break;case"d":e[2]==="r"?o=H(e.slice(2),!0,n.cache,!0)||"":e[2]==="d"?o=H(e,!1,!1,!1)||"":e[2]==="D"?o=H(e,!0,!1,!1)||"":o=H(e,!1,n.cache,!1)||"";break;default:ve();break}return o||void 0}function Pe(e){Ee();let t=we(e,Pe);return t&&r2.log(t),!0}function Ve(){r2.unload("core",y),r2.plugin("core",function(){function e(t){if(t.startsWith(y)){let o=t.slice(y.length).trim();return Pe(o)}return!1}return{name:y,license:"MIT",desc:"r2 decompiler based on r2ai",call:e}})}Ve();
