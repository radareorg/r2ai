import llama_cpp

model_path="/Users/pancake/.r2ai.models/";
# model_path+="unsloth.Q4_K_M.gguf"
# model_path+= "llama-3-tsuki-unsloth-8b.Q5_K_M.gguf"
model_path+= "llama-2-7b-chat-codeCherryPop.Q5_K_M.gguf"
# model_path += "mistral-7b-instruct-v0.2.Q5_K_M.gguf"
peers = [
	["@kelsy", "act as a twitter user responding in one short sentence your first though on my messages, be constructive and help me discuss ideas"],
	["@john", "act as a twitter user, be concise, respond in one short sentence be funny, help me reason my plans"],
	["@anna", "respond in one short sentence with philosophical reasoning on my message"],
	["@tony", "behave like a shy twitter user, respond with one or two short sentences, as a software developer, respond in short but wise sentence reasoning the best plans for implementing the topic"]
]

logs = []

ai = llama_cpp.Llama(model_path=model_path, verbose=False, n_ctx=8096)

def context(msg):
	global logs
	ats = [word for word in msg.split() if word.startswith('@')]
	ctx = []
	for log in logs:
		if log == msg:
			continue
		if len(ats) > 0 and any(at in log for at in ats):
			ctx.append(log)
		if not log.startswith("@"):
		 	ctx.append(log)
	return ctx
		
def sortedpeers(msg):
	global peers
	ats = [word for word in msg.split() if word.startswith('@')]
	if len(ats) == 0:
		return peers
	ps = []
	for peer in peers:
		if any(at in peer[0] for at in ats):
			ps.insert(0, peer)
		else:
			ps.append(peer)
	return ps

def chat(msg):
	logs.append(msg)
	global ai
	for peer in sortedpeers(msg):
		ctx = ",".join(context(msg))
		m = f"[INST]{peer[1]}[/INST] {msg}"
		m = f"[INST]{peer[1]}[/INST] Consider this context: {ctx}. Respond to: {msg}```"
		m = f"[INST]{peer[1]}[/INST] <s>{ctx}</s>. Respond in one sentence to: {msg}```"
		mm = ai(m, max_tokens=-1)
		r = mm["choices"][0]["text"]
		r = "".join(r.split("\n"))
		reply = f"{peer[0]}: {r}"
		logs.append(reply)
		print(f"\x1b[31m{reply}\x1b[0m")

# res = ai("Hello")
# print(res["choices"][0]["text"])


while True:
	msg = input()
	if not msg:
		break
	chat(msg)
