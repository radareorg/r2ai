📦
23357 /main.js
✄
var D="1.2.6",b="decai",O="Transform this pseudocode and respond ONLY with plain code (NO explanations, comments or markdown), Change 'goto' into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and strings from comments like 'string:', Reduce lines of code and fit everything in a single function, Remove all dead code",C={decai:`# Using Decai

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
`};var r={decopipe:{use:!1},host:"http://localhost",port:"11434",baseurl:"",api:"ollama",pipeline:"",commands:"pdc",yolo:!1,tts:!1,language:"C",humanLanguage:"English",deterministic:!0,debug:!1,think:-1,useFiles:!1,contextFile:"",model:"",cache:!1,maxInputTokens:-1,prompt:O,lastOutput:""};function F(e){return(r2.cmd("-e dir.tmp").trim()??".")+"/"+e}function _(e){return r2.cmd2("test -h").logs[0].message.indexOf("-fdx")!==-1?!0:r2.cmd("'test -vf "+e).startsWith("found")}function R(e,t){return e+" ".repeat(Math.max(0,t-e.length))}function j(e){return e.replace(/\x1b\[[0-9;]*m/g,"")}function Y(e){let t=e.match(/```json\s*([\s\S]*?)```/);return t&&t[1]?t[1].trim():e}function J(e){let t=e,o=t.indexOf("{");o!==-1&&(t=t.slice(o));let i=t.indexOf("}");return i!==-1&&(t=t.slice(0,i+1)),t}function S(e){return btoa(e)}function G(e,t){let o=S(t);r2.cmd("p6ds "+o+" > "+e)}function k(e){let t=e;return r.think!==2&&(t=t.replace(/<think>[\s\S]*?<\/think>/gi,"")),t.split(`
`).filter(o=>!o.trim().startsWith("```")).join(`
`)}function q(e){r.debug&&console.log(e)}function $(e){let t={};for(let o of e.split(/\r?\n/)){let i=o.trim();if(!i||i.startsWith("#"))continue;let[s,...a]=i.split("=");if(!s||a.length===0)continue;let c=a.join("=").trim();t[s.toLowerCase()]=c}return t}var ne={mistral:"MISTRAL_API_KEY",anthropic:"ANTHROPIC_API_KEY",huggingface:"HUGGINGFACE_API_KEY",openai:"OPENAI_API_KEY",gemini:"GEMINI_API_KEY",deepseek:"DEEPSEEK_API_KEY",xai:"XAI_API_KEY",ollama:"OLLAMA_API_KEY",ollamacloud:"OLLAMA_API_KEY"};function A(e,t){let o=r2.cmd("'%"+t).trim();if(o.indexOf("=")===-1&&o!=="")return[o.trim(),null,"env"];let i=e.toLowerCase(),s="~/.config/r2ai/apikeys.txt";if(_(s)){let c=r2.cmd("'cat "+s),n=$(c);if(Object.keys(n).indexOf(i)!==-1)return[n[i],null,"txt"]}let a="~/.r2ai."+i+"-key";if(_(a)){let c=r2.cmd("'cat "+a);return c===""?[null,"Cannot read "+a,"no"]:[c.trim(),null,"file"]}return[null,"Not available","nope"]}function H(){r2.cmd("'ed ~/.config/r2ai/apikeys.txt")}function N(){Object.entries(ne).forEach(([e,t])=>{let o=A(e,t)[2];console.log(o,"	",e)})}function se(e){let{method:t,url:o,headers:i,payload:s}=e,a=["curl","-s",o];if(i.forEach(c=>a.push("-H",`"${c}"`)),a.push("-H",'"Content-Type: application/json"'),t==="POST"){if(!s)throw new Error("Payload required for POST requests");let c=r2.fdump(s);a.push("-d",`'@${c}'`);let n=a.join(" ")+" && rm "+c;return q(n),r2.syscmds(n)}else{let c=a.join(" ");return q(c),r2.syscmds(c)}}function ie(e){if(e==="")throw new Error("empty response");try{return JSON.parse(e)}catch(t){let o=t;throw console.error("output:",e),console.error(o,o.stack),new Error(o.message||"JSON parse error")}}function W(e){try{let t=se(e);try{return ie(t)}catch(o){return{error:o.message}}}catch(t){return{error:t.message}}}function E(e,t){return W({method:"GET",url:e,headers:t})}function V(e,t,o){return W({method:"POST",url:e,headers:t,payload:o})}function K(e,t,o){let i=E(e,t);return i.error?(console.error(i.error),"error invalid response"):i.data?.map(o).join(`
`)||""}var ae=e=>{let t=r.baseurl||r.host+":"+r.port;return K(`${t}/api/tags`,[],o=>o.name)},B=e=>{let t;if(e.requiresAuth&&e.authKey&&(t=A(e.authKey.split("_")[0].toLowerCase(),e.authKey),t&&t[1]))throw new Error(t[1]);let i=(r.baseurl||e.defaultBaseurl)+"/v1/models",s=t?["Authorization: Bearer "+t[0]]:[];return K(i,s,a=>a.id)},z=e=>{let t=A("anthropic","ANTHROPIC_API_KEY");if(t&&t[1])throw new Error(t[1]);let i=(r.baseurl||e.defaultBaseurl)+"/v1/models",s=["x-api-key: "+t[0],"anthropic-version: 2023-06-01"];return K(i,s,a=>a.id)},le=e=>{let t=A("mistral","MISTRAL_API_KEY");if(t&&t[1])throw new Error(t[1]);let i=(r.baseurl||e.defaultBaseurl)+"/v1/models",s=["Authorization: Bearer "+t[0]],a=E(i,s);return a.data?(n=>n.filter((l,u,p)=>p.findIndex(d=>d.name===l.name)===u))(a.data).map(n=>[R(n.name||n.id,30),R(""+(n.max_context_length||""),10),n.description||""].join(" ")).join(`
`):""},Q={anthropic:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseurl:"https://api.anthropic.com",requiresAuth:!0,authKey:"ANTHROPIC_API_KEY",apiStyle:"anthropic",listModelsCallback:z},claude:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseurl:"https://api.anthropic.com",requiresAuth:!0,authKey:"ANTHROPIC_API_KEY",apiStyle:"anthropic",listModelsCallback:z},openai:{defaultModel:"gpt-4o-mini",defaultBaseurl:"https://api.openai.com",requiresAuth:!0,authKey:"OPENAI_API_KEY",apiStyle:"openai",listModelsCallback:B},ollama:{defaultModel:"qwen2.5-coder:latest",defaultBaseurl:"http://localhost:11434",requiresAuth:!1,apiStyle:"ollama",listModelsCallback:ae},ollamacloud:{defaultModel:"gpt-oss:120b",defaultBaseurl:"https://ollama.com",requiresAuth:!0,authKey:"OLLAMA_API_KEY",apiStyle:"openai",listModelsCallback:B},gemini:{defaultModel:"gemini-2.5-flash",defaultBaseurl:"https://generativelanguage.googleapis.com",requiresAuth:!0,authKey:"GEMINI_API_KEY",apiStyle:"gemini",hardcodedModels:["gemini-2.0-flash","gemini-2.0-flash-lite","gemini-2.5-pro","gemini-2.5-flash","gemini-2.5-flash-lite"]},mistral:{defaultModel:"codestral-latest",defaultBaseurl:"https://api.mistral.ai",requiresAuth:!0,authKey:"MISTRAL_API_KEY",apiStyle:"openai",listModelsCallback:le},xai:{defaultModel:"grok-beta",defaultBaseurl:"https://api.x.ai",requiresAuth:!0,authKey:"XAI_API_KEY",apiStyle:"openai",hardcodedModels:["grok-2","grok-beta"]},lmstudio:{defaultModel:"local-model",defaultBaseurl:"http://127.0.0.1:1234",requiresAuth:!1,apiStyle:"openai",listModelsCallback:B},deepseek:{defaultModel:"deepseek-coder",defaultBaseurl:"https://api.deepseek.com",requiresAuth:!0,authKey:"DEEPSEEK_API_KEY",apiStyle:"openai",hardcodedModels:["deepseek-coder","deepseek-chat"]}};function T(e){return Q[e]}function L(){return Object.keys(Q)}function ce(e,t){let o=e;return r.think>=0&&(r.think===0?(o+=' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".',o+=" /no_think"):r.think>0&&(o="Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer."+o)),t?o:r.prompt+ue()+o}function ue(){return`
.Translate the code into `+r.language+` programming language
`}function I(e,t,o,i,s,a,c){let n=r.model||e.defaultModel,l=ce(t,o),u;if(e.requiresAuth&&e.authKey&&(u=A(e.authKey.split("_")[0].toLowerCase(),e.authKey),u[1]))return`Cannot read ~/.r2ai.${e.authKey.split("_")[0].toLowerCase()}-key`;let p=i(n,l,e),d=r.baseurl||e.defaultBaseurl,m=a(d,n,u&&u[0]?u[0]:void 0),w=c(u?u[0]:null,e);try{let h=V(m,w,JSON.stringify(p));return s(h)}catch(h){return"ERROR: "+h.message}}function de(e,t,o){return I(e,t,o,(n,l)=>({stream:!1,model:n,messages:[{role:"user",content:l}]}),n=>{if(n.error&&typeof n.error=="object"&&n.error.message)throw new Error(n.error.message);if(n.choices&&n.choices[0]?.message?.content)return k(n.choices[0].message.content);throw new Error("Invalid response format")},(n,l)=>n+"/v1/chat/completions",n=>n?["Authorization: Bearer "+n]:[])}function pe(e,t,o){return e.authKey?I(e,t,o,(n,l)=>{let u={model:n,max_tokens:5128,messages:[{role:"user",content:l}]};return r.deterministic&&Object.assign(u,{temperature:0,top_p:0,top_k:1}),u},n=>{if(n.content&&n.content[0]?.text)return k(n.content[0].text);if(n.error){let l=typeof n.error=="object"?n.error.message:n.error;throw new Error(l||"Unknown error")}throw new Error("Invalid response format")},(n,l)=>n+"/v1/messages",n=>["anthropic-version: 2023-06-01","x-api-key: "+n]):"ERROR: No auth key configured"}function me(e,t,o){return I(e,t,o,(n,l)=>{let u={stream:!1,model:n,messages:[{role:"user",content:l}]};return r.deterministic&&(u.options={repeat_last_n:0,top_p:0,top_k:1,temperature:0,repeat_penalty:1,seed:123}),u},n=>{if(n&&n.error){let l=typeof n.error=="string"?n.error:JSON.stringify(n.error);throw new Error(l)}if(n.message&&n.message.content)return k(n.message.content);throw new Error(JSON.stringify(n))},(n,l)=>n+"/api/chat",()=>[])}function fe(e,t,o){return e.authKey?I(e,t,o,(n,l)=>{let u={contents:[{parts:[{text:l}]}]};return r.deterministic&&(u.generationConfig={temperature:0,topP:1,topK:1}),u},n=>{let l=n;if(l.candidates&&l.candidates[0]?.content?.parts?.[0]?.text)return k(l.candidates[0].content.parts[0].text);throw l.error?new Error(typeof l.error=="string"?l.error:JSON.stringify(l.error)):(console.log(JSON.stringify(l)),new Error("Invalid response format"))},(n,l,u)=>`${n}/v1beta/models/${l}:generateContent?key=${u}`,()=>[]):"ERROR: No auth key configured"}function X(e,t){let o=T(r.api);if(!o)return`Unknown value for 'decai -e api'. Available: ${L().join(", ")}`;switch(o.apiStyle){case"openai":return de(o,e,t);case"anthropic":return pe(o,e,t);case"ollama":return me(o,e,t);case"gemini":return fe(o,e,t);default:return`Unsupported API style: ${o.apiStyle}`}}function Z(e){let t=T(e);if(!t){console.error(`Unknown provider: ${e}`);return}try{let o="";t.listModelsCallback&&(o=t.listModelsCallback(t)),o&&console.log(o),t.hardcodedModels&&t.hardcodedModels.forEach(i=>console.log(i)),e==="mistral"&&console.log("ministral-8b-latest"),!o&&!t.hardcodedModels&&console.log(t.defaultModel)}catch(o){let i=o;console.error(`Error listing models for ${e}:`,i.message),console.log(t.defaultModel)}}var v={pipeline:{get:()=>r.pipeline,set:e=>{r.pipeline=e;try{r.decopipe=JSON.parse(r2.cmd("cat "+e))}catch(t){console.error(t)}}},model:{get:()=>r.model,set:e=>{e==="?"?Z(r.api):r.model=e.trim()}},deterministic:{get:()=>r.deterministic,set:e=>{r.deterministic=e==="true"||e==="1"}},files:{get:()=>r.useFiles,set:e=>{r.useFiles=e==="true"}},think:{get:()=>r.think,set:e=>{r.think=e==="true"?1:e==="false"?0:+e}},debug:{get:()=>r.debug,set:e=>{r.debug=e==="true"||e==="1"}},api:{get:()=>r.api,set:e=>{if(e==="?"){let t=L().join(`
`);console.error(t)}else r.api=e}},lang:{get:()=>r.language,set:e=>{r.language=e}},hlang:{get:()=>r.humanLanguage,set:e=>{r.humanLanguage=e}},cache:{get:()=>r.cache,set:e=>{r.cache=e==="true"||e==="1"}},cmds:{get:()=>r.commands,set:e=>{r.commands=e}},tts:{get:()=>r.tts,set:e=>{r.tts=e==="true"||e==="1"}},yolo:{get:()=>r.yolo,set:e=>{r.yolo=e==="true"||e==="1"}},prompt:{get:()=>r.prompt,set:e=>{r.prompt=e}},ctxfile:{get:()=>r.contextFile,set:e=>{r.contextFile=e}},baseurl:{get:()=>r.baseurl,set:e=>{r.baseurl=e}},maxtokens:{get:()=>r.maxInputTokens,set:e=>{r.maxInputTokens=parseInt(e,10)||-1}}};function x(e){let t=e.indexOf("="),o=t===-1?e:e.slice(0,t),i=t===-1?void 0:e.slice(t+1);if(!v[o]){console.error("Unknown config key");return}typeof i<"u"?v[o].set(i):console.log(v[o].get())}function ee(){Object.keys(v).forEach(e=>{let t=v[e].get();console.log("decai -e "+e+"="+t)})}function f(e,t,o=!1){let i=(t||"").replace(/`/g,""),s=e.replace(/'/g,"");if(r.api==="r2"||r.api==="r2ai"){let c=F(".pdc.txt");G(c,i);let n=s.startsWith("-")?s:["-i",c,s].join(" "),u=(r.baseurl?r.baseurl+"/cmd":r.host+":"+r.port+"/cmd")+"/"+n.replace(/ /g,"%20").replace(/'/g,"\\'"),p=E(u,[]);return p.error?`Error: ${p.error}`:p.result||JSON.stringify(p)||"Cannot curl, use r2ai-server or r2ai -w"}if(s.startsWith("-"))return"";let a=s+`:
`+i;return r.maxInputTokens>0&&a.length>r.maxInputTokens&&(a=a.slice(0,r.maxInputTokens)),X(a,o)}function te(){let e="",t=o=>e+=" "+b+" "+o+`
`;e+="Usage: "+b+` (-h) ...
`,e+="Version: "+D+`
`,t("-a [query]    - solve query with auto mode"),t("-b [url]      - set base URL (alias for decai -e baseurl)"),t("-d [f1 ..]    - decompile given functions"),t("-dd [..]      - same as above, but ignoring cache"),t("-dD [query]   - decompile current function with given extra query"),t("-dr           - decompile function and its called ones (recursive)"),t("-e            - display and change eval config vars"),t("-h            - show this help"),t("-H            - help setting up r2ai"),t("-i [f] [q]    - include given file and query"),t("-k            - list API key status"),t("-K            - edit apikeys.txt"),t("-m [model]    - use -m? or -e model=? to list the available models"),t("-n            - suggest better function name"),t("-p [provider] - same as decai -e api (will be provider)"),t("-q [text]     - query language model with given text"),t("-Q [text]     - query on top of the last output"),t("-r [prompt]   - change role prompt (same as: decai -e prompt)"),t("-R            - reset role prompt to default prompt"),t("-s            - function signature"),t("-v            - show local variables"),t("-V            - find vulnerabilities"),t("-x[*]         - eXplain current function (-x* for r2 script)"),r2.log(e.trim())}function M(e,t,o,i){if(o){let n=r2.cmd("anos").trim();if(n.length>0)return n}let s="";if(i){let n=r2.cmd("s");s+=`## Context functions:
`;let l=r2.cmdAt("axff~^C[2]~$$",n);for(let u of l.split(/\n/g))s+=r2.cmd("pdc@"+u);r2.cmd("s "+n)}let a=t?" "+e:"",c=r2.cmd("e scr.color");try{let n=e.slice(2).trim(),l=0,u="";r.contextFile!==""&&r2.cmd2("test -f "+r.contextFile).value===0&&(u+=`## Context:
[START]
`+r2.cmd("cat "+r.contextFile)+`
[END]
`),r2.cmd("e scr.color=0");let p=`## Before:
`;for(let m of r.commands.split(",")){if(m.trim()==="")continue;let w=t||n.trim().length===0?m:m+"@@= "+n,h=r2.cmd(w);h.length>5&&(p+="Output of "+m+`:
[START]
`+h+`
[END]
`,l++)}if(p+=`## After:
`,r2.cmd("e scr.color="+c),l===0){console.error("Nothing to do.");return}let d="";if(r.decopipe.use){let m=r.decopipe[r.decopipe.default],w=r.model,h=u+p;for(let P of m.pipeline){P.model&&(r.model=P.model);let U=P.query+". "+m.globalQuery;d=f(U,h,!0),r.debug&&console.log(`QUERY
`,U,`
INPUT
`,h,`
OUTPUT
`,d),h=d}d=h,r.model=w}else{let m=a;u+=p+s,d=f(m,u,!1),r.lastOutput=d}return o&&d.length>1&&r2.call("ano=base64:"+S(d)),d.startsWith("```")&&(d=d.replace(/```.*\n/,"").replace(/```$/,"")),d.trim()}catch(n){r2.cmd("e scr.color="+c);let l=n;console.error(l,l.stack);return}}function he(){let e=r2.cmd("e scr.color");r2.cmd("e scr.color=0");let t="[START]"+r.commands.split(",").map(s=>r2.cmd(s)).join(`
`)+"[END]";r2.cmd("e scr.color="+e);let i=f("Analyze function calls, references, comments and strings, loops and ignore registers and memory accesses. Explain the purpose of this function in a single short sentence. /no_think Do not introduce or argue the response, translation of the explanation in "+r.humanLanguage,t,!0).trim().split(/\n/g);return i[i.length-1].trim()}function ge(){let e=r.language,t=r2.cmd("afv;pdc");r.language="C";let o="'afs "+f("analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the return. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",t,!1),i=o.indexOf("{");return i!==-1&&(o=o.substring(0,i)),r.language=e,o}function ye(e,t){let o=[];for(;;){let i=C.auto;if(o.length>0){i+=`## Command Results

`;for(let a of o){let c=JSON.parse(a);i+="### "+c.command+"\n\n```\n"+c.response+"\n```\n"}}i+=`

## User Prompt

`+e,r.debug&&console.log(`#### input
`,i,`
#### /input`),console.log("Thinking...");let s=f("",i,!0);r.debug&&console.log(`#### output
`,s,`
#### /output`);try{let a=JSON.parse(J(Y(k(s))));if(a.action==="r2cmd"||a.action==="response"||a.action===a.command){let c=a.command||"";a.reason&&(console.log("[r2cmd] Reasoning: "+a.reason),r.tts&&(r2.syscmd("pkill say"),r2.syscmd("say -v Alex -r 250 '"+a.reason.replace(/'/g,"")+"' &"))),console.log("[r2cmd] Action: "+a.description),console.log("[r2cmd] Command: "+c);let n=c;r.yolo||(n=be(c,t)),console.log("[r2cmd] Running: "+n);let l=r2.cmd2(n),u=l.logs?l.logs.map(m=>m.type+": "+m.message).join(`
`):"",p=(l.res+u).trim();console.log(p);let d=j(p);r.debug&&console.log(`<r2output>
`,d,`
<(r2output>`),o.push(JSON.stringify({action:"response",command:n,description:a.description,response:d}))}else if(a.action==="reply"){console.log(`Done
`,a.response);break}else console.log(`Unknown response
`,JSON.stringify(s))}catch(a){let c=s.indexOf('response": "');if(c!==-1){let n=s.slice(c+12).replace(/\\n/g,`
`).replace(/\\/g,"");console.log(n)}else console.log(s),console.error(a);break}}}function be(e,t){for(;;){let o=r2.cmd("'?ie Tweak command? ('?' for help)").trim();if(o==="q!"){console.error("Break!");break}if(o==="?"){ke();continue}else if(o.startsWith(":")){console.log(r2.cmd(o.slice(1)));continue}else if(o.startsWith("-e")){t(o);continue}else{if(o==="!")return"?e do NOT execute '"+e+"' again, continue without it";if(o.startsWith("!")){console.log(r2.syscmd(o.slice(1)));continue}else{if(o==="q")return"?e All data collected!. Do not call more commands, reply the solutions";if(o){let i=o.indexOf("#");return i!==-1?o.slice(0,i).trim():o}else return e}}}return e}function ke(){console.log(" '!'     do not run this command"),console.log(" '!c'    run system command"),console.log(" 'q'     to quit auto and try to solve"),console.log(" 'q!'    quit auto without solving"),console.log(" 'c # C' use given command with comment"),console.log(" ':c'    run r2 command without feeding auto"),console.log(" '-e'    set decai configuration variables")}function oe(e,t){if(e===""||!e.startsWith("-")){te();return}let o="";switch(e[1]){case"H":console.log(C.decai);break;case"a":ye(e.slice(2).trim(),t);break;case"m":{let s=e.slice(2).trim();s==="="?x("model="):s?x("model="+s):x("model");break}case"n":case"f":{o=r2.cmd("axff~$[3]");let s=r2.cmd("fd.").trim().split(/\n/).filter(a=>!a.startsWith("secti")).join(",");o=f("give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: "+s,o,!1).trim(),o+=" @ "+r2.cmd("?v $FB").trim();break}case"v":o=r2.cmd("afv;pdc"),o=f("guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",o,!1);break;case"i":{let s=e.slice(2).trim().split(/ /g);if(s.length>=2){let a=s[0],c=s.slice(1).join(" "),n=r2.cmd("cat "+a);console.log(f(c,n,!0))}else console.log("Use: decai -i [file] [query ...]");break}case"p":{let s=e.slice(2).trim();s?x("api="+s):N();break}case"r":{let s=e.slice(2).trim();s?r.prompt=s:console.log(r.prompt);break}case"R":r.prompt=O;break;case"s":o=ge();break;case"V":o=f("find vulnerabilities, dont show the code, only show the response, provide a sample exploit",r.lastOutput,!1);break;case"K":H();break;case"k":N();break;case"b":{let s=e.slice(2).trim();s?x("baseurl="+s):console.log(r.baseurl);break}case"e":{let s=e.slice(2).trim();s?x(s):ee();break}case"q":try{o=f(e.slice(2).trim(),null,!0)}catch(s){let a=s;console.error(a,a.stack)}break;case"Q":o=f(e.slice(2).trim(),r.lastOutput,!1);break;case"x":o=he(),(e[2]==="*"||e[2]==="r")&&(o="'CC "+o);break;case"d":e[2]==="r"?o=M(e.slice(2),!0,r.cache,!0)||"":e[2]==="d"?o=M(e,!1,!1,!1)||"":e[2]==="D"?o=M(e,!0,!1,!1)||"":o=M(e,!1,r.cache,!1)||"";break;default:te();break}return o||void 0}function re(e){let t=oe(e,re);return t&&r2.log(t),!0}function xe(){r2.unload("core",b),r2.plugin("core",function(){function e(t){if(t.startsWith(b)){let o=t.slice(b.length).trim();return re(o)}return!1}return{name:b,license:"MIT",desc:"r2 decompiler based on r2ai",call:e}})}xe();
