📦
24273 /main.js
✄
var U="1.2.6",k="decai",P="Transform this pseudocode and respond ONLY with plain code (NO explanations, comments or markdown), Change 'goto' into if/else/for/while, Simplify as much as possible, use better variable names, take function arguments and strings from comments like 'string:', Reduce lines of code and fit everything in a single function, Remove all dead code",C={decai:`# Using Decai

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
`};var n={decopipe:{use:!1},host:"http://localhost",port:"11434",baseurl:"",api:"ollama",pipeline:"",commands:"pdc",yolo:!1,tts:!1,language:"C",humanLanguage:"English",deterministic:!0,debug:!1,think:-1,useFiles:!1,contextFile:"",model:"",cache:!1,maxInputTokens:-1,prompt:P,lastOutput:""};function F(e){return(r2.cmd("-e dir.tmp").trim()??".")+"/"+e}function N(e){return r2.cmd2("test -h").logs[0].message.indexOf("-fdx")!==-1?!0:r2.cmd("'test -vf "+e).startsWith("found")}function K(e,t){return e+" ".repeat(Math.max(0,t-e.length))}function D(e){return e.replace(/\x1b\[[0-9;]*m/g,"")}function B(e){let t=e.match(/```json\s*([\s\S]*?)```/);return t&&t[1]?t[1].trim():e}function Y(e){let t=e,o=t.indexOf("{");o!==-1&&(t=t.slice(o));let s=t.indexOf("}");return s!==-1&&(t=t.slice(0,s+1)),t}function S(e){return btoa(e)}function $(e,t){let o=S(t);r2.cmd("p6ds "+o+" > "+e)}function x(e){let t=e;return n.think!==2&&(t=t.replace(/<think>[\s\S]*?<\/think>/gi,"")),t.split(`
`).filter(o=>!o.trim().startsWith("```")).join(`
`)}function E(e){n.debug&&console.log(e)}function J(e){let t={};for(let o of e.split(/\r?\n/)){let s=o.trim();if(!s||s.startsWith("#"))continue;let[r,...a]=s.split("=");if(!r||a.length===0)continue;let u=a.join("=").trim();t[r.toLowerCase()]=u}return t}var ee={mistral:"MISTRAL_API_KEY",anthropic:"ANTHROPIC_API_KEY",huggingface:"HUGGINGFACE_API_KEY",openai:"OPENAI_API_KEY",gemini:"GEMINI_API_KEY",deepseek:"DEEPSEEK_API_KEY",xai:"XAI_API_KEY",ollama:"OLLAMA_API_KEY",ollamacloud:"OLLAMA_API_KEY"};function y(e,t){let o=r2.cmd("'%"+t).trim();if(o.indexOf("=")===-1&&o!=="")return[o.trim(),null,"env"];let s=e.toLowerCase(),r="~/.config/r2ai/apikeys.txt";if(N(r)){let u=r2.cmd("'cat "+r),c=J(u);if(Object.keys(c).indexOf(s)!==-1)return[c[s],null,"txt"]}let a="~/.r2ai."+s+"-key";if(N(a)){let u=r2.cmd("'cat "+a);return u===""?[null,"Cannot read "+a,"no"]:[u.trim(),null,"file"]}return[null,"Not available","nope"]}function G(){r2.cmd("'ed ~/.config/r2ai/apikeys.txt")}function q(){Object.entries(ee).forEach(([e,t])=>{let o=y(e,t)[2];console.log(o,"	",e)})}function O(e,t){let o=t.map(r=>`-H "${r}"`).join(" "),s=`curl -s ${e} ${o} -H "Content-Type: application/json"`;return JSON.parse(r2.syscmds(s))}function v(e,t,o){let s=t.map(i=>`-H "${i}"`).join(" "),r=(i,l,p)=>{let d=p.replace(/'/g,"'\\''"),m=`curl -s '${i}' ${l} -d '${d}' -H "Content-Type: application/json"`;return E(m),r2.syscmds(m)},a=(i,l,p)=>{let d=r2.fdump(p),m=`curl -s '${i}' ${l} -d '@${d}' -H "Content-Type: application/json"`;E(m);let w=r2.syscmd(m);return r2.syscmd("rm "+d),w},c=(n.useFiles?a:r)(e,s,o);if(c==="")return{error:"empty response"};try{return JSON.parse(c)}catch(i){let l=i;return console.error("output:",c),console.error(l,l.stack),{error:l.stack}}}var H={anthropic:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseurl:"https://api.anthropic.com",requiresAuth:!0,authKey:"ANTHROPIC_API_KEY",apiStyle:"anthropic",hardcodedModels:["claude-3-5-sonnet-20241022","claude-3-7-sonnet-20250219","claude-opus-4-20250514","claude-sonnet-4-20250514"]},claude:{defaultModel:"claude-3-7-sonnet-20250219",defaultBaseurl:"https://api.anthropic.com",requiresAuth:!0,authKey:"ANTHROPIC_API_KEY",apiStyle:"anthropic",hardcodedModels:["claude-3-5-sonnet-20241022","claude-3-7-sonnet-20250219","claude-opus-4-20250514","claude-sonnet-4-20250514"]},openai:{defaultModel:"gpt-4o-mini",defaultBaseurl:"https://api.openai.com",requiresAuth:!0,authKey:"OPENAI_API_KEY",apiStyle:"openai",dynamicModels:!0},ollama:{defaultModel:"qwen2.5-coder:latest",defaultBaseurl:"http://localhost:11434",requiresAuth:!1,apiStyle:"ollama",dynamicModels:!0},ollamacloud:{defaultModel:"gpt-oss:120b",defaultBaseurl:"https://ollama.com",requiresAuth:!0,authKey:"OLLAMA_API_KEY",apiStyle:"openai",dynamicModels:!0},gemini:{defaultModel:"gemini-2.5-flash",defaultBaseurl:"https://generativelanguage.googleapis.com",requiresAuth:!0,authKey:"GEMINI_API_KEY",apiStyle:"gemini",hardcodedModels:["gemini-2.0-flash","gemini-2.0-flash-lite","gemini-2.5-pro","gemini-2.5-flash","gemini-2.5-flash-lite"]},mistral:{defaultModel:"codestral-latest",defaultBaseurl:"https://api.mistral.ai",requiresAuth:!0,authKey:"MISTRAL_API_KEY",apiStyle:"openai",dynamicModels:!0,hardcodedModels:["codestral-latest"]},xai:{defaultModel:"grok-beta",defaultBaseurl:"https://api.x.ai",requiresAuth:!0,authKey:"XAI_API_KEY",apiStyle:"openai",hardcodedModels:["grok-2","grok-beta"]},lmstudio:{defaultModel:"local-model",defaultBaseurl:"http://127.0.0.1:1234",requiresAuth:!1,apiStyle:"openai",hardcodedModels:["local-model"]},deepseek:{defaultModel:"deepseek-coder",defaultBaseurl:"https://api.deepseek.com",requiresAuth:!0,authKey:"DEEPSEEK_API_KEY",apiStyle:"openai",hardcodedModels:["deepseek-coder","deepseek-chat"]}};function T(e){return H[e]}function L(){return Object.keys(H)}function M(e,t){let o=e;return n.think>=0&&(n.think===0?(o+=' Answers directly and concisely, without showing any thinking steps or internal reasoning. Never include phrases like "Let me think".',o+=" /no_think"):n.think>0&&(o="Think step by step and explain the reasoning process, When answering, first output your reasoning inside <think> and </think> tags, then give the final answer."+o)),t?o:n.prompt+te()+o}function te(){return`
.Translate the code into `+n.language+` programming language
`}function oe(e,t,o){let s=n.model||e.defaultModel,r=M(t,o),a={stream:!1,model:s,messages:[{role:"user",content:r}]},c=(n.baseurl||e.defaultBaseurl)+"/v1/chat/completions",i=[];if(e.requiresAuth&&e.authKey){let l=y(e.authKey.split("_")[0].toLowerCase(),e.authKey);if(l[1])return`Cannot read ~/.r2ai.${e.authKey.split("_")[0].toLowerCase()}-key`;i=["Authorization: Bearer "+l[0]]}try{let l=v(c,i,JSON.stringify(a));if(l.error&&typeof l.error=="object"&&l.error.message)throw new Error(l.error.message);if(l.choices&&l.choices[0]?.message?.content)return x(l.choices[0].message.content);throw new Error("Invalid response format")}catch(l){return"ERROR: "+l.message}}function ne(e,t,o){if(!e.authKey)return"ERROR: No auth key configured";let s=y(e.authKey.split("_")[0].toLowerCase(),e.authKey);if(s[1])return`Cannot read ~/.r2ai.${e.authKey.split("_")[0].toLowerCase()}-key`;let r=n.model||e.defaultModel,a=M(t,o),u={model:r,max_tokens:5128,messages:[{role:"user",content:a}]};n.deterministic&&Object.assign(u,{temperature:0,top_p:0,top_k:1});let c=["anthropic-version: 2023-06-01","x-api-key: "+s[0]];try{let i=v(e.defaultBaseurl+"/v1/messages",c,JSON.stringify(u));if(i.content&&i.content[0]?.text)return x(i.content[0].text);if(i.error){let l=typeof i.error=="object"?i.error.message:i.error;throw new Error(l||"Unknown error")}throw new Error("Invalid response format")}catch(i){return"ERROR: "+i.message}}function re(e,t,o){let s=n.model||e.defaultModel,r=M(t,o),a={stream:!1,model:s,messages:[{role:"user",content:r}]};n.deterministic&&(a.options={repeat_last_n:0,top_p:0,top_k:1,temperature:0,repeat_penalty:1,seed:123});let c=(n.baseurl||e.defaultBaseurl)+"/api/chat";try{let i=v(c,[],JSON.stringify(a));if(i&&i.error){let l=typeof i.error=="string"?i.error:JSON.stringify(i.error);throw new Error(l)}if(i.message&&i.message.content)return x(i.message.content);throw new Error(JSON.stringify(i))}catch(i){let l=i;return console.error(l.stack),"ERROR: "+l.message}}function se(e,t,o){if(!e.authKey)return"ERROR: No auth key configured";let s=y(e.authKey.split("_")[0].toLowerCase(),e.authKey);if(s[1])return`Cannot read ~/.r2ai.${e.authKey.split("_")[0].toLowerCase()}-key`;let r=n.model||e.defaultModel,u={contents:[{parts:[{text:M(t,o)}]}]};n.deterministic&&(u.generationConfig={temperature:0,topP:1,topK:1});let c=`${e.defaultBaseurl}/v1beta/models/${r}:generateContent?key=${s[0]}`;try{let i=v(c,[],JSON.stringify(u));if(i.candidates&&i.candidates[0]?.content?.parts?.[0]?.text)return x(i.candidates[0].content.parts[0].text);throw i.error?new Error(typeof i.error=="string"?i.error:JSON.stringify(i.error)):(console.log(JSON.stringify(i)),new Error("Invalid response format"))}catch(i){return"ERROR: "+i.message}}function W(e,t){let o=T(n.api);if(!o)return`Unknown value for 'decai -e api'. Available: ${L().join(", ")}`;switch(o.apiStyle){case"openai":return oe(o,e,t);case"anthropic":return ne(o,e,t);case"ollama":return re(o,e,t);case"gemini":return se(o,e,t);default:return`Unsupported API style: ${o.apiStyle}`}}function ie(){let e=y("anthropic","ANTHROPIC_API_KEY");if(e[1])throw new Error(e[1]);let t=["x-api-key: "+e[0],"anthropic-version: 2023-06-01"],o=O("https://api.anthropic.com/v1/models",t);return o.data?o.data.map(s=>s.id).join(`
`):""}function ae(){let e=y("mistral","MISTRAL_API_KEY");if(e[1])throw new Error(e[1]);let t=["Authorization: Bearer "+e[0]],o=O("https://api.mistral.ai/v1/models",t);return o.data?(r=>r.filter((a,u,c)=>c.findIndex(i=>i.name===a.name)===u))(o.data).map(r=>[K(r.name||r.id,30),K(""+(r.max_context_length||""),10),r.description||""].join(" ")).join(`
`):""}function le(){let e=y("openai","OPENAI_API_KEY");if(e[1])throw new Error(e[1]);let t=["Authorization: Bearer "+e[0]],o=O("https://api.openai.com/v1/models",t);return o.data?o.data.map(s=>s.id).join(`
`):""}function ce(){let t=`curl -s ${n.baseurl||n.host+":"+n.port}/api/tags`,o=r2.syscmds(t);try{let s=JSON.parse(o);return s.models?s.models.map(r=>r.name).join(`
`):""}catch(s){return console.error(s),console.log(o),"error invalid response"}}function ue(){let e=y("ollama","OLLAMA_API_KEY");if(e[1])throw new Error(e[1]);let t=["Authorization: Bearer "+e[0]],o=O("https://ollama.com/v1/models",t);return o.data?o.data.map(s=>s.id).join(`
`):""}function z(e){let t=T(e);if(!t){console.error(`Unknown provider: ${e}`);return}try{switch(e){case"ollama":case"openapi":console.log(ce());break;case"lmstudio":case"openai":console.log(le());break;case"claude":case"anthropic":console.log(ie()),t.hardcodedModels&&t.hardcodedModels.forEach(o=>console.log(o));break;case"mistral":console.log(ae()),console.log("codestral-latest");break;case"ollamacloud":console.log(ue());break;default:t.hardcodedModels?console.log(t.hardcodedModels.join(`
`)):console.log(t.defaultModel);break}}catch(o){let s=o;console.error(`Error listing models for ${e}:`,s.message),console.log(t.defaultModel)}}var I={pipeline:{get:()=>n.pipeline,set:e=>{n.pipeline=e;try{n.decopipe=JSON.parse(r2.cmd("cat "+e))}catch(t){console.error(t)}}},model:{get:()=>n.model,set:e=>{e==="?"?z(n.api):n.model=e.trim()}},deterministic:{get:()=>n.deterministic,set:e=>{n.deterministic=e==="true"||e==="1"}},files:{get:()=>n.useFiles,set:e=>{n.useFiles=e==="true"}},think:{get:()=>n.think,set:e=>{n.think=e==="true"?1:e==="false"?0:+e}},debug:{get:()=>n.debug,set:e=>{n.debug=e==="true"||e==="1"}},api:{get:()=>n.api,set:e=>{if(e==="?"){let t=L().join(`
`);console.error(t)}else n.api=e}},lang:{get:()=>n.language,set:e=>{n.language=e}},hlang:{get:()=>n.humanLanguage,set:e=>{n.humanLanguage=e}},cache:{get:()=>n.cache,set:e=>{n.cache=e==="true"||e==="1"}},cmds:{get:()=>n.commands,set:e=>{n.commands=e}},tts:{get:()=>n.tts,set:e=>{n.tts=e==="true"||e==="1"}},yolo:{get:()=>n.yolo,set:e=>{n.yolo=e==="true"||e==="1"}},prompt:{get:()=>n.prompt,set:e=>{n.prompt=e}},ctxfile:{get:()=>n.contextFile,set:e=>{n.contextFile=e}},baseurl:{get:()=>n.baseurl,set:e=>{n.baseurl=e}},maxtokens:{get:()=>n.maxInputTokens,set:e=>{n.maxInputTokens=parseInt(e,10)||-1}}};function A(e){let t=e.indexOf("="),o=t===-1?e:e.slice(0,t),s=t===-1?void 0:e.slice(t+1);if(!I[o]){console.error("Unknown config key");return}typeof s<"u"?I[o].set(s):console.log(I[o].get())}function V(){Object.keys(I).forEach(e=>{let t=I[e].get();console.log("decai -e "+e+"="+t)})}function f(e,t,o=!1){let s=(t||"").replace(/`/g,""),r=e.replace(/'/g,"");if(n.api==="r2"||n.api==="r2ai"){let u=F(".pdc.txt");$(u,s);let c=r.startsWith("-")?r:["-i",u,r].join(" "),i=n.baseurl?n.baseurl+"/cmd":n.host+":"+n.port+"/cmd",l=c.replace(/ /g,"%20").replace(/'/g,"\\'"),p='curl -s "'+i+"/"+l+'" || echo "Cannot curl, use r2ai-server or r2ai -w"';return E(p),r2.syscmds(p)}if(r.startsWith("-"))return"";let a=r+`:
`+s;return n.maxInputTokens>0&&a.length>n.maxInputTokens&&(a=a.slice(0,n.maxInputTokens)),W(a,o)}function Q(){let e="",t=o=>e+=" "+k+" "+o+`
`;e+="Usage: "+k+` (-h) ...
`,e+="Version: "+U+`
`,t("-a [query]    - solve query with auto mode"),t("-b [url]      - set base URL (alias for decai -e baseurl)"),t("-d [f1 ..]    - decompile given functions"),t("-dd [..]      - same as above, but ignoring cache"),t("-dD [query]   - decompile current function with given extra query"),t("-dr           - decompile function and its called ones (recursive)"),t("-e            - display and change eval config vars"),t("-h            - show this help"),t("-H            - help setting up r2ai"),t("-i [f] [q]    - include given file and query"),t("-k            - list API key status"),t("-K            - edit apikeys.txt"),t("-m [model]    - use -m? or -e model=? to list the available models"),t("-n            - suggest better function name"),t("-p [provider] - same as decai -e api (will be provider)"),t("-q [text]     - query language model with given text"),t("-Q [text]     - query on top of the last output"),t("-r [prompt]   - change role prompt (same as: decai -e prompt)"),t("-R            - reset role prompt to default prompt"),t("-s            - function signature"),t("-v            - show local variables"),t("-V            - find vulnerabilities"),t("-x[*]         - eXplain current function (-x* for r2 script)"),r2.log(e.trim())}function _(e,t,o,s){if(o){let c=r2.cmd("anos").trim();if(c.length>0)return c}let r="";if(s){let c=r2.cmd("s");r+=`## Context functions:
`;let i=r2.cmdAt("axff~^C[2]~$$",c);for(let l of i.split(/\n/g))r+=r2.cmd("pdc@"+l);r2.cmd("s "+c)}let a=t?" "+e:"",u=r2.cmd("e scr.color");try{let c=e.slice(2).trim(),i=0,l="";n.contextFile!==""&&r2.cmd2("test -f "+n.contextFile).value===0&&(l+=`## Context:
[START]
`+r2.cmd("cat "+n.contextFile)+`
[END]
`),r2.cmd("e scr.color=0");let p=`## Before:
`;for(let m of n.commands.split(",")){if(m.trim()==="")continue;let w=t||c.trim().length===0?m:m+"@@= "+c,b=r2.cmd(w);b.length>5&&(p+="Output of "+m+`:
[START]
`+b+`
[END]
`,i++)}if(p+=`## After:
`,r2.cmd("e scr.color="+u),i===0){console.error("Nothing to do.");return}let d="";if(n.decopipe.use){let m=n.decopipe[n.decopipe.default],w=n.model,b=l+p;for(let R of m.pipeline){R.model&&(n.model=R.model);let j=R.query+". "+m.globalQuery;d=f(j,b,!0),n.debug&&console.log(`QUERY
`,j,`
INPUT
`,b,`
OUTPUT
`,d),b=d}d=b,n.model=w}else{let m=a;l+=p+r,d=f(m,l,!1),n.lastOutput=d}return o&&d.length>1&&r2.call("ano=base64:"+S(d)),d.startsWith("```")&&(d=d.replace(/```.*\n/,"").replace(/```$/,"")),d.trim()}catch(c){r2.cmd("e scr.color="+u);let i=c;console.error(i,i.stack);return}}function de(){let e=r2.cmd("e scr.color");r2.cmd("e scr.color=0");let t="[START]"+n.commands.split(",").map(r=>r2.cmd(r)).join(`
`)+"[END]";r2.cmd("e scr.color="+e);let s=f("Analyze function calls, references, comments and strings, loops and ignore registers and memory accesses. Explain the purpose of this function in a single short sentence. /no_think Do not introduce or argue the response, translation of the explanation in "+n.humanLanguage,t,!0).trim().split(/\n/g);return s[s.length-1].trim()}function me(){let e=n.language,t=r2.cmd("afv;pdc");n.language="C";let o="'afs "+f("analyze the uses of the arguments and return value to infer the signature, identify which is the correct type for the return. Do NOT print the function body, ONLY output the function signature, like if it was going to be used in a C header",t,!1),s=o.indexOf("{");return s!==-1&&(o=o.substring(0,s)),n.language=e,o}function pe(e,t){let o=[];for(;;){let s=C.auto;if(o.length>0){s+=`## Command Results

`;for(let a of o){let u=JSON.parse(a);s+="### "+u.command+"\n\n```\n"+u.response+"\n```\n"}}s+=`

## User Prompt

`+e,n.debug&&console.log(`#### input
`,s,`
#### /input`),console.log("Thinking...");let r=f("",s,!0);n.debug&&console.log(`#### output
`,r,`
#### /output`);try{let a=JSON.parse(Y(B(x(r))));if(a.action==="r2cmd"||a.action==="response"||a.action===a.command){let u=a.command||"";a.reason&&(console.log("[r2cmd] Reasoning: "+a.reason),n.tts&&(r2.syscmd("pkill say"),r2.syscmd("say -v Alex -r 250 '"+a.reason.replace(/'/g,"")+"' &"))),console.log("[r2cmd] Action: "+a.description),console.log("[r2cmd] Command: "+u);let c=u;n.yolo||(c=fe(u,t)),console.log("[r2cmd] Running: "+c);let i=r2.cmd2(c),l=i.logs?i.logs.map(m=>m.type+": "+m.message).join(`
`):"",p=(i.res+l).trim();console.log(p);let d=D(p);n.debug&&console.log(`<r2output>
`,d,`
<(r2output>`),o.push(JSON.stringify({action:"response",command:c,description:a.description,response:d}))}else if(a.action==="reply"){console.log(`Done
`,a.response);break}else console.log(`Unknown response
`,JSON.stringify(r))}catch(a){let u=r.indexOf('response": "');if(u!==-1){let c=r.slice(u+12).replace(/\\n/g,`
`).replace(/\\/g,"");console.log(c)}else console.log(r),console.error(a);break}}}function fe(e,t){for(;;){let o=r2.cmd("'?ie Tweak command? ('?' for help)").trim();if(o==="q!"){console.error("Break!");break}if(o==="?"){he();continue}else if(o.startsWith(":")){console.log(r2.cmd(o.slice(1)));continue}else if(o.startsWith("-e")){t(o);continue}else{if(o==="!")return"?e do NOT execute '"+e+"' again, continue without it";if(o.startsWith("!")){console.log(r2.syscmd(o.slice(1)));continue}else{if(o==="q")return"?e All data collected!. Do not call more commands, reply the solutions";if(o){let s=o.indexOf("#");return s!==-1?o.slice(0,s).trim():o}else return e}}}return e}function he(){console.log(" '!'     do not run this command"),console.log(" '!c'    run system command"),console.log(" 'q'     to quit auto and try to solve"),console.log(" 'q!'    quit auto without solving"),console.log(" 'c # C' use given command with comment"),console.log(" ':c'    run r2 command without feeding auto"),console.log(" '-e'    set decai configuration variables")}function X(e,t){if(e===""||!e.startsWith("-")){Q();return}let o="";switch(e[1]){case"H":console.log(C.decai);break;case"a":pe(e.slice(2).trim(),t);break;case"m":{let r=e.slice(2).trim();r==="="?A("model="):r?A("model="+r):A("model");break}case"n":case"f":{o=r2.cmd("axff~$[3]");let r=r2.cmd("fd.").trim().split(/\n/).filter(a=>!a.startsWith("secti")).join(",");o=f("give me a better name for this function. the output must be: 'afn NEWNAME'. do not include the function code, only the afn line. consider: "+r,o,!1).trim(),o+=" @ "+r2.cmd("?v $FB").trim();break}case"v":o=r2.cmd("afv;pdc"),o=f("guess a better name and type for each local variable and function argument taking using. output an r2 script using afvn and afvt commands",o,!1);break;case"i":{let r=e.slice(2).trim().split(/ /g);if(r.length>=2){let a=r[0],u=r.slice(1).join(" "),c=r2.cmd("cat "+a);console.log(f(u,c,!0))}else console.log("Use: decai -i [file] [query ...]");break}case"p":{let r=e.slice(2).trim();r?A("api="+r):q();break}case"r":{let r=e.slice(2).trim();r?n.prompt=r:console.log(n.prompt);break}case"R":n.prompt=P;break;case"s":o=me();break;case"V":o=f("find vulnerabilities, dont show the code, only show the response, provide a sample exploit",n.lastOutput,!1);break;case"K":G();break;case"k":q();break;case"b":{let r=e.slice(2).trim();r?A("baseurl="+r):console.log(n.baseurl);break}case"e":{let r=e.slice(2).trim();r?A(r):V();break}case"q":try{o=f(e.slice(2).trim(),null,!0)}catch(r){let a=r;console.error(a,a.stack)}break;case"Q":o=f(e.slice(2).trim(),n.lastOutput,!1);break;case"x":o=de(),(e[2]==="*"||e[2]==="r")&&(o="'CC "+o);break;case"d":e[2]==="r"?o=_(e.slice(2),!0,n.cache,!0)||"":e[2]==="d"?o=_(e,!1,!1,!1)||"":e[2]==="D"?o=_(e,!0,!1,!1)||"":o=_(e,!1,n.cache,!1)||"";break;default:Q();break}return o||void 0}function Z(e){let t=X(e,Z);return t&&r2.log(t),!0}function ge(){r2.unload("core",k),r2.plugin("core",function(){function e(t){if(t.startsWith(k)){let o=t.slice(k.length).trim();return Z(o)}return!1}return{name:k,license:"MIT",desc:"r2 decompiler based on r2ai",call:e}})}ge();
