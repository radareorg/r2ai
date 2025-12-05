📦
23857 /main.js
✄
var L="1.2.6",k="decai",P="Transform this pseudocode and respond ONLY with plain code (NO explanations, comments or markdown), Change 'goto' into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and strings from comments like 'string:', Reduce lines of code and fit everything in a single function, Remove all dead code",C={decai:`# Using Decai

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
`};var n={decopipe:{use:!1},host:"http://localhost",port:"11434",baseurl:"",api:"ollama",pipeline:"",commands:"pdc",yolo:!1,tts:!1,language:"C",humanLanguage:"English",deterministic:!0,debug:!1,think:-1,useFiles:!1,contextFile:"",model:"",cache:!1,maxInputTokens:-1,prompt:P,lastOutput:""};function j(e){return(r2.cmd("-e dir.tmp").trim()??".")+"/"+e}function N(e){return r2.cmd2("test -h").logs[0].message.indexOf("-fdx")!==-1?!0:r2.cmd("'test -vf "+e).startsWith("found")}function R(e,t){return e+" ".repeat(Math.max(0,t-e.length))}function U(e){return e.replace(/\x1b\[[0-9;]*m/g,"")}function F(e){let t=e.match(/```json\s*([\s\S]*?)```/);return t&&t[1]?t[1].trim():e}function D(e){let t=e,o=t.indexOf("{");o!==-1&&(t=t.slice(o));let i=t.indexOf("}");return i!==-1&&(t=t.slice(0,i+1)),t}function S(e){return btoa(e)}function Y(e,t){let o=S(t);r2.cmd("p6ds "+o+" > "+e)}function A(e){let t=e;return n.think!==2&&(t=t.replace(/<think>[\s\S]*?<\/think>/gi,"")),t.split(`
`).filter(o=>!o.trim().startsWith("```")).join(`
`)}function v(e){n.debug&&console.log(e)}function $(e){let t={};for(let o of e.split(/\r?\n/)){let i=o.trim();if(!i||i.startsWith("#"))continue;let[s,...l]=i.split("=");if(!s||l.length===0)continue;let u=l.join("=").trim();t[s.toLowerCase()]=u}return t}var te={mistral:"MISTRAL_API_KEY",anthropic:"ANTHROPIC_API_KEY",huggingface:"HUGGINGFACE_API_KEY",openai:"OPENAI_API_KEY",gemini:"GEMINI_API_KEY",deepseek:"DEEPSEEK_API_KEY",xai:"XAI_API_KEY",ollama:"OLLAMA_API_KEY",ollamacloud:"OLLAMA_API_KEY"};function b(e,t){let o=r2.cmd("'%"+t).trim();if(o.indexOf("=")===-1&&o!=="")return[o.trim(),null,"env"];let i=e.toLowerCase(),s="~/.config/r2ai/apikeys.txt";if(N(s)){let u=r2.cmd("'cat "+s),r=$(u);if(Object.keys(r).indexOf(i)!==-1)return[r[i],null,"txt"]}let l="~/.r2ai."+i+"-key";if(N(l)){let u=r2.cmd("'cat "+l);return u===""?[null,"Cannot read "+l,"no"]:[u.trim(),null,"file"]}return[null,"Not available","nope"]}function J(){r2.cmd("'ed ~/.config/r2ai/apikeys.txt")}function q(){Object.entries(te).forEach(([e,t])=>{let o=b(e,t)[2];console.log(o,"	",e)})}function G(e,t){let o=t.map(s=>`-H "${s}"`).join(" "),i=`curl -s ${e} ${o} -H "Content-Type: application/json"`;return JSON.parse(r2.syscmds(i))}function H(e,t,o){let i=t.map(a=>`-H "${a}"`).join(" "),s=(a,c,m)=>{let d=m.replace(/'/g,"'\\''"),p=`curl -s '${a}' ${c} -d '${d}' -H "Content-Type: application/json"`;return v(p),r2.syscmds(p)},l=(a,c,m)=>{let d=r2.fdump(m),p=`curl -s '${a}' ${c} -d '@${d}' -H "Content-Type: application/json"`;v(p);let x=r2.syscmd(p);return r2.syscmd("rm "+d),x},r=(n.useFiles?l:s)(e,i,o);if(r==="")return{error:"empty response"};try{return JSON.parse(r)}catch(a){let c=a;return console.error("output:",r),console.error(c,c.stack),{error:c.stack}}}var W={anthropic:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseurl:"https://api.anthropic.com",requiresAuth:!0,authKey:"ANTHROPIC_API_KEY",apiStyle:"anthropic",hardcodedModels:["claude-3-5-sonnet-20241022","claude-3-7-sonnet-20250219","claude-opus-4-20250514","claude-sonnet-4-20250514"]},claude:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseurl:"https://api.anthropic.com",requiresAuth:!0,authKey:"ANTHROPIC_API_KEY",apiStyle:"anthropic",hardcodedModels:["claude-3-5-sonnet-20241022","claude-3-7-sonnet-20250219","claude-opus-4-20250514","claude-sonnet-4-20250514"]},openai:{defaultModel:"gpt-4o-mini",defaultBaseurl:"https://api.openai.com",requiresAuth:!0,authKey:"OPENAI_API_KEY",apiStyle:"openai",dynamicModels:!0},ollama:{defaultModel:"qwen2.5-coder:latest",defaultBaseurl:"http://localhost:11434",requiresAuth:!1,apiStyle:"ollama",dynamicModels:!0},ollamacloud:{defaultModel:"gpt-oss:120b",defaultBaseurl:"https://ollama.com",requiresAuth:!0,authKey:"OLLAMA_API_KEY",apiStyle:"openai",dynamicModels:!0},gemini:{defaultModel:"gemini-2.5-flash",defaultBaseurl:"https://generativelanguage.googleapis.com",requiresAuth:!0,authKey:"GEMINI_API_KEY",apiStyle:"gemini",hardcodedModels:["gemini-2.0-flash","gemini-2.0-flash-lite","gemini-2.5-pro","gemini-2.5-flash","gemini-2.5-flash-lite"]},mistral:{defaultModel:"codestral-latest",defaultBaseurl:"https://api.mistral.ai",requiresAuth:!0,authKey:"MISTRAL_API_KEY",apiStyle:"openai",dynamicModels:!0,hardcodedModels:["codestral-latest"]},xai:{defaultModel:"grok-beta",defaultBaseurl:"https://api.x.ai",requiresAuth:!0,authKey:"XAI_API_KEY",apiStyle:"openai",hardcodedModels:["grok-2","grok-beta"]},lmstudio:{defaultModel:"local-model",defaultBaseurl:"http://127.0.0.1:1234",requiresAuth:!1,apiStyle:"openai",hardcodedModels:["local-model"]},deepseek:{defaultModel:"deepseek-coder",defaultBaseurl:"https://api.deepseek.com",requiresAuth:!0,authKey:"DEEPSEEK_API_KEY",apiStyle:"openai",hardcodedModels:["deepseek-coder","deepseek-chat"]}};function K(e){return W[e]}function B(){return Object.keys(W)}function oe(e,t){let o=e;return n.think>=0&&(n.think===0?(o+=' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".',o+=" /no_think"):n.think>0&&(o="Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer."+o)),t?o:n.prompt+ne()+o}function ne(){return`
.Translate the code into `+n.language+` programming language
`}function I(e,t,o,i,s,l,u){let r=n.model||e.defaultModel,a=oe(t,o),c;if(e.requiresAuth&&e.authKey&&(c=b(e.authKey.split("_")[0].toLowerCase(),e.authKey),c[1]))return`Cannot read ~/.r2ai.${e.authKey.split("_")[0].toLowerCase()}-key`;let m=i(r,a,e),d=n.baseurl||e.defaultBaseurl,p=l(d,r,c&&c[0]?c[0]:void 0),x=u(c?c[0]:null,e);try{let h=H(p,x,JSON.stringify(m));return s(h)}catch(h){return"ERROR: "+h.message}}function re(e,t,o){return I(e,t,o,(r,a)=>({stream:!1,model:r,messages:[{role:"user",content:a}]}),r=>{if(r.error&&typeof r.error=="object"&&r.error.message)throw new Error(r.error.message);if(r.choices&&r.choices[0]?.message?.content)return A(r.choices[0].message.content);throw new Error("Invalid response format")},(r,a)=>r+"/v1/chat/completions",r=>r?["Authorization: Bearer "+r]:[])}function se(e,t,o){return e.authKey?I(e,t,o,(r,a)=>{let c={model:r,max_tokens:5128,messages:[{role:"user",content:a}]};return n.deterministic&&Object.assign(c,{temperature:0,top_p:0,top_k:1}),c},r=>{if(r.content&&r.content[0]?.text)return A(r.content[0].text);if(r.error){let a=typeof r.error=="object"?r.error.message:r.error;throw new Error(a||"Unknown error")}throw new Error("Invalid response format")},(r,a)=>r+"/v1/messages",r=>["anthropic-version: 2023-06-01","x-api-key: "+r]):"ERROR: No auth key configured"}function ie(e,t,o){return I(e,t,o,(r,a)=>{let c={stream:!1,model:r,messages:[{role:"user",content:a}]};return n.deterministic&&(c.options={repeat_last_n:0,top_p:0,top_k:1,temperature:0,repeat_penalty:1,seed:123}),c},r=>{if(r&&r.error){let a=typeof r.error=="string"?r.error:JSON.stringify(r.error);throw new Error(a)}if(r.message&&r.message.content)return A(r.message.content);throw new Error(JSON.stringify(r))},(r,a)=>r+"/api/chat",()=>[])}function ae(e,t,o){return e.authKey?I(e,t,o,(r,a)=>{let c={contents:[{parts:[{text:a}]}]};return n.deterministic&&(c.generationConfig={temperature:0,topP:1,topK:1}),c},r=>{let a=r;if(a.candidates&&a.candidates[0]?.content?.parts?.[0]?.text)return A(a.candidates[0].content.parts[0].text);throw a.error?new Error(typeof a.error=="string"?a.error:JSON.stringify(a.error)):(console.log(JSON.stringify(a)),new Error("Invalid response format"))},(r,a,c)=>`${r}/v1beta/models/${a}:generateContent?key=${c}`,()=>[]):"ERROR: No auth key configured"}function z(e,t){let o=K(n.api);if(!o)return`Unknown value for 'decai -e api'. Available: ${B().join(", ")}`;switch(o.apiStyle){case"openai":return re(o,e,t);case"anthropic":return se(o,e,t);case"ollama":return ie(o,e,t);case"gemini":return ae(o,e,t);default:return`Unsupported API style: ${o.apiStyle}`}}function M(e,t,o){let i=G(e,t);return i.data?o(i.data):""}function le(){let e=b("anthropic","ANTHROPIC_API_KEY");if(e[1])throw new Error(e[1]);let t=["x-api-key: "+e[0],"anthropic-version: 2023-06-01"];return M("https://api.anthropic.com/v1/models",t,o=>o.map(i=>i.id).join(`
`))}function ce(){let e=b("mistral","MISTRAL_API_KEY");if(e[1])throw new Error(e[1]);let t=["Authorization: Bearer "+e[0]];return M("https://api.mistral.ai/v1/models",t,o=>o?(s=>s.filter((l,u,r)=>r.findIndex(a=>a.name===l.name)===u))(o).map(s=>[R(s.name||s.id,30),R(""+(s.max_context_length||""),10),s.description||""].join(" ")).join(`
`):"")}function ue(){let e=b("openai","OPENAI_API_KEY");if(e[1])throw new Error(e[1]);let t=["Authorization: Bearer "+e[0]];return M("https://api.openai.com/v1/models",t,o=>o.map(i=>i.id).join(`
`))}function de(){let t=`curl -s ${n.baseurl||n.host+":"+n.port}/api/tags`,o=r2.syscmds(t);try{let i=JSON.parse(o);return i.models?i.models.map(s=>s.name).join(`
`):""}catch(i){return console.error(i),console.log(o),"error invalid response"}}function pe(){let e=b("ollama","OLLAMA_API_KEY");if(e[1])throw new Error(e[1]);let t=["Authorization: Bearer "+e[0]];return M("https://ollama.com/v1/models",t,o=>o.map(i=>i.id).join(`
`))}function V(e){let t=K(e);if(!t){console.error(`Unknown provider: ${e}`);return}try{switch(e){case"ollama":case"openapi":console.log(de());break;case"lmstudio":case"openai":console.log(ue());break;case"claude":case"anthropic":console.log(le()),t.hardcodedModels&&t.hardcodedModels.forEach(o=>console.log(o));break;case"mistral":console.log(ce()),console.log("codestral-latest");break;case"ollamacloud":console.log(pe());break;default:t.hardcodedModels?console.log(t.hardcodedModels.join(`
`)):console.log(t.defaultModel);break}}catch(o){let i=o;console.error(`Error listing models for ${e}:`,i.message),console.log(t.defaultModel)}}var E={pipeline:{get:()=>n.pipeline,set:e=>{n.pipeline=e;try{n.decopipe=JSON.parse(r2.cmd("cat "+e))}catch(t){console.error(t)}}},model:{get:()=>n.model,set:e=>{e==="?"?V(n.api):n.model=e.trim()}},deterministic:{get:()=>n.deterministic,set:e=>{n.deterministic=e==="true"||e==="1"}},files:{get:()=>n.useFiles,set:e=>{n.useFiles=e==="true"}},think:{get:()=>n.think,set:e=>{n.think=e==="true"?1:e==="false"?0:+e}},debug:{get:()=>n.debug,set:e=>{n.debug=e==="true"||e==="1"}},api:{get:()=>n.api,set:e=>{if(e==="?"){let t=B().join(`
`);console.error(t)}else n.api=e}},lang:{get:()=>n.language,set:e=>{n.language=e}},hlang:{get:()=>n.humanLanguage,set:e=>{n.humanLanguage=e}},cache:{get:()=>n.cache,set:e=>{n.cache=e==="true"||e==="1"}},cmds:{get:()=>n.commands,set:e=>{n.commands=e}},tts:{get:()=>n.tts,set:e=>{n.tts=e==="true"||e==="1"}},yolo:{get:()=>n.yolo,set:e=>{n.yolo=e==="true"||e==="1"}},prompt:{get:()=>n.prompt,set:e=>{n.prompt=e}},ctxfile:{get:()=>n.contextFile,set:e=>{n.contextFile=e}},baseurl:{get:()=>n.baseurl,set:e=>{n.baseurl=e}},maxtokens:{get:()=>n.maxInputTokens,set:e=>{n.maxInputTokens=parseInt(e,10)||-1}}};function w(e){let t=e.indexOf("="),o=t===-1?e:e.slice(0,t),i=t===-1?void 0:e.slice(t+1);if(!E[o]){console.error("Unknown config key");return}typeof i<"u"?E[o].set(i):console.log(E[o].get())}function Q(){Object.keys(E).forEach(e=>{let t=E[e].get();console.log("decai -e "+e+"="+t)})}function f(e,t,o=!1){let i=(t||"").replace(/`/g,""),s=e.replace(/'/g,"");if(n.api==="r2"||n.api==="r2ai"){let u=j(".pdc.txt");Y(u,i);let r=s.startsWith("-")?s:["-i",u,s].join(" "),a=n.baseurl?n.baseurl+"/cmd":n.host+":"+n.port+"/cmd",c=r.replace(/ /g,"%20").replace(/'/g,"\\'"),m='curl -s "'+a+"/"+c+'" || echo "Cannot curl, use r2ai-server or r2ai -w"';return v(m),r2.syscmds(m)}if(s.startsWith("-"))return"";let l=s+`:
`+i;return n.maxInputTokens>0&&l.length>n.maxInputTokens&&(l=l.slice(0,n.maxInputTokens)),z(l,o)}function X(){let e="",t=o=>e+=" "+k+" "+o+`
`;e+="Usage: "+k+` (-h) ...
`,e+="Version: "+L+`
`,t("-a [query]    - solve query with auto mode"),t("-b [url]      - set base URL (alias for decai -e baseurl)"),t("-d [f1 ..]    - decompile given functions"),t("-dd [..]      - same as above, but ignoring cache"),t("-dD [query]   - decompile current function with given extra query"),t("-dr           - decompile function and its called ones (recursive)"),t("-e            - display and change eval config vars"),t("-h            - show this help"),t("-H            - help setting up r2ai"),t("-i [f] [q]    - include given file and query"),t("-k            - list API key status"),t("-K            - edit apikeys.txt"),t("-m [model]    - use -m? or -e model=? to list the available models"),t("-n            - suggest better function name"),t("-p [provider] - same as decai -e api (will be provider)"),t("-q [text]     - query language model with given text"),t("-Q [text]     - query on top of the last output"),t("-r [prompt]   - change role prompt (same as: decai -e prompt)"),t("-R            - reset role prompt to default prompt"),t("-s            - function signature"),t("-v            - show local variables"),t("-V            - find vulnerabilities"),t("-x[*]         - eXplain current function (-x* for r2 script)"),r2.log(e.trim())}function _(e,t,o,i){if(o){let r=r2.cmd("anos").trim();if(r.length>0)return r}let s="";if(i){let r=r2.cmd("s");s+=`## Context functions:
`;let a=r2.cmdAt("axff~^C[2]~$$",r);for(let c of a.split(/\n/g))s+=r2.cmd("pdc@"+c);r2.cmd("s "+r)}let l=t?" "+e:"",u=r2.cmd("e scr.color");try{let r=e.slice(2).trim(),a=0,c="";n.contextFile!==""&&r2.cmd2("test -f "+n.contextFile).value===0&&(c+=`## Context:
[START]
`+r2.cmd("cat "+n.contextFile)+`
[END]
`),r2.cmd("e scr.color=0");let m=`## Before:
`;for(let p of n.commands.split(",")){if(p.trim()==="")continue;let x=t||r.trim().length===0?p:p+"@@= "+r,h=r2.cmd(x);h.length>5&&(m+="Output of "+p+`:
[START]
`+h+`
[END]
`,a++)}if(m+=`## After:
`,r2.cmd("e scr.color="+u),a===0){console.error("Nothing to do.");return}let d="";if(n.decopipe.use){let p=n.decopipe[n.decopipe.default],x=n.model,h=c+m;for(let O of p.pipeline){O.model&&(n.model=O.model);let T=O.query+". "+p.globalQuery;d=f(T,h,!0),n.debug&&console.log(`QUERY
`,T,`
INPUT
`,h,`
OUTPUT
`,d),h=d}d=h,n.model=x}else{let p=l;c+=m+s,d=f(p,c,!1),n.lastOutput=d}return o&&d.length>1&&r2.call("ano=base64:"+S(d)),d.startsWith("```")&&(d=d.replace(/```.*\n/,"").replace(/```$/,"")),d.trim()}catch(r){r2.cmd("e scr.color="+u);let a=r;console.error(a,a.stack);return}}function me(){let e=r2.cmd("e scr.color");r2.cmd("e scr.color=0");let t="[START]"+n.commands.split(",").map(s=>r2.cmd(s)).join(`
`)+"[END]";r2.cmd("e scr.color="+e);let i=f("Analyze function calls, references, comments and strings, loops and ignore registers and memory accesses. Explain the purpose of this function in a single short sentence. /no_think Do not introduce or argue the response, translation of the explanation in "+n.humanLanguage,t,!0).trim().split(/\n/g);return i[i.length-1].trim()}function fe(){let e=n.language,t=r2.cmd("afv;pdc");n.language="C";let o="'afs "+f("analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the return. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",t,!1),i=o.indexOf("{");return i!==-1&&(o=o.substring(0,i)),n.language=e,o}function he(e,t){let o=[];for(;;){let i=C.auto;if(o.length>0){i+=`## Command Results

`;for(let l of o){let u=JSON.parse(l);i+="### "+u.command+"\n\n```\n"+u.response+"\n```\n"}}i+=`

## User Prompt

`+e,n.debug&&console.log(`#### input
`,i,`
#### /input`),console.log("Thinking...");let s=f("",i,!0);n.debug&&console.log(`#### output
`,s,`
#### /output`);try{let l=JSON.parse(D(F(A(s))));if(l.action==="r2cmd"||l.action==="response"||l.action===l.command){let u=l.command||"";l.reason&&(console.log("[r2cmd] Reasoning: "+l.reason),n.tts&&(r2.syscmd("pkill say"),r2.syscmd("say -v Alex -r 250 '"+l.reason.replace(/'/g,"")+"' &"))),console.log("[r2cmd] Action: "+l.description),console.log("[r2cmd] Command: "+u);let r=u;n.yolo||(r=ge(u,t)),console.log("[r2cmd] Running: "+r);let a=r2.cmd2(r),c=a.logs?a.logs.map(p=>p.type+": "+p.message).join(`
`):"",m=(a.res+c).trim();console.log(m);let d=U(m);n.debug&&console.log(`<r2output>
`,d,`
<(r2output>`),o.push(JSON.stringify({action:"response",command:r,description:l.description,response:d}))}else if(l.action==="reply"){console.log(`Done
`,l.response);break}else console.log(`Unknown response
`,JSON.stringify(s))}catch(l){let u=s.indexOf('response": "');if(u!==-1){let r=s.slice(u+12).replace(/\\n/g,`
`).replace(/\\/g,"");console.log(r)}else console.log(s),console.error(l);break}}}function ge(e,t){for(;;){let o=r2.cmd("'?ie Tweak command? ('?' for help)").trim();if(o==="q!"){console.error("Break!");break}if(o==="?"){ye();continue}else if(o.startsWith(":")){console.log(r2.cmd(o.slice(1)));continue}else if(o.startsWith("-e")){t(o);continue}else{if(o==="!")return"?e do NOT execute '"+e+"' again, continue without it";if(o.startsWith("!")){console.log(r2.syscmd(o.slice(1)));continue}else{if(o==="q")return"?e All data collected!. Do not call more commands, reply the solutions";if(o){let i=o.indexOf("#");return i!==-1?o.slice(0,i).trim():o}else return e}}}return e}function ye(){console.log(" '!'     do not run this command"),console.log(" '!c'    run system command"),console.log(" 'q'     to quit auto and try to solve"),console.log(" 'q!'    quit auto without solving"),console.log(" 'c # C' use given command with comment"),console.log(" ':c'    run r2 command without feeding auto"),console.log(" '-e'    set decai configuration variables")}function Z(e,t){if(e===""||!e.startsWith("-")){X();return}let o="";switch(e[1]){case"H":console.log(C.decai);break;case"a":he(e.slice(2).trim(),t);break;case"m":{let s=e.slice(2).trim();s==="="?w("model="):s?w("model="+s):w("model");break}case"n":case"f":{o=r2.cmd("axff~$[3]");let s=r2.cmd("fd.").trim().split(/\n/).filter(l=>!l.startsWith("secti")).join(",");o=f("give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: "+s,o,!1).trim(),o+=" @ "+r2.cmd("?v $FB").trim();break}case"v":o=r2.cmd("afv;pdc"),o=f("guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",o,!1);break;case"i":{let s=e.slice(2).trim().split(/ /g);if(s.length>=2){let l=s[0],u=s.slice(1).join(" "),r=r2.cmd("cat "+l);console.log(f(u,r,!0))}else console.log("Use: decai -i [file] [query ...]");break}case"p":{let s=e.slice(2).trim();s?w("api="+s):q();break}case"r":{let s=e.slice(2).trim();s?n.prompt=s:console.log(n.prompt);break}case"R":n.prompt=P;break;case"s":o=fe();break;case"V":o=f("find vulnerabilities, dont show the code, only show the response, provide a sample exploit",n.lastOutput,!1);break;case"K":J();break;case"k":q();break;case"b":{let s=e.slice(2).trim();s?w("baseurl="+s):console.log(n.baseurl);break}case"e":{let s=e.slice(2).trim();s?w(s):Q();break}case"q":try{o=f(e.slice(2).trim(),null,!0)}catch(s){let l=s;console.error(l,l.stack)}break;case"Q":o=f(e.slice(2).trim(),n.lastOutput,!1);break;case"x":o=me(),(e[2]==="*"||e[2]==="r")&&(o="'CC "+o);break;case"d":e[2]==="r"?o=_(e.slice(2),!0,n.cache,!0)||"":e[2]==="d"?o=_(e,!1,!1,!1)||"":e[2]==="D"?o=_(e,!0,!1,!1)||"":o=_(e,!1,n.cache,!1)||"";break;default:X();break}return o||void 0}function ee(e){let t=Z(e,ee);return t&&r2.log(t),!0}function ke(){r2.unload("core",k),r2.plugin("core",function(){function e(t){if(t.startsWith(k)){let o=t.slice(k.length).trim();return ee(o)}return!1}return{name:k,license:"MIT",desc:"r2 decompiler based on r2ai",call:e}})}ke();
