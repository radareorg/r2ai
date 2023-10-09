(function() {
class R2AI {
	constructor (num, model) {
		r2.call(`r2ai -n ${num}`)
		// r2.call('r2ai -e DEBUG=1')
		this.model = model;
	}
	reset() {
		r2.call('r2ai -R')
	}
	setRole(msg) {
		r2.call(`r2ai -r ${msg}`)
	}
	query(msg) {
		if (msg == '') {
			return '';
		}
		r2.call(`r2ai -m ${this.model}`)
		const fmsg = msg.trim().replace(/\n/g, '.');
		return r2.call(`r2ai ${fmsg}`)
	}
}

function filter(msg) {
	const fmsg = msg.split(/\n/g).map((x)=>x.trim()).join('').replace(/#/g,'').replace(/"/g,'').replace(/'/g, "").replace(/`/g,'').replace(/\*/g, '').split(/\n/).join('.').trim();
	// const fmsg = msg.split(/\n/g)[0].replace(/#/g,'').replace(/"/g,'').replace(/'/g, "").replace(/`/g,'').replace(/\*/g, '').trim();
	return fmsg;
}
function say(voice, msg) {
	const fmsg = filter(msg);
	console.log(voice + ': ' + fmsg);
	r2.cmd(`'!say -v ${voice} "${fmsg}"`)
}

// const ai = new R2AI(0, 'codellama-13b-python.ggmlv3.Q4_1.gguf');
// const ai = new R2AI(0, 'llama-2-7b-chat-codeCherryPop.ggmlv3.q4_K_M.gguf');
const ai = new R2AI(0, 'llama-2-7b-chat-codeCherryPop.ggmlv3.q4_K_M.gguf');
// const ai = new R2AI(0, 'models/models/guanaco-7b-uncensored.Q2_K.gguf');
const ai2 = new R2AI(1, 'models/models/wizardlm-1.0-uncensored-llama2-13b.Q2_K.gguf'); // models/models/guanaco-7b-uncensored.Q2_K.gguf');

/*
ai.setRole('i am a journalist, ask WHY for reasons, use ONLY one sentence. ask about low level details');
ai2.setRole('act as an expert in ARM architecture. make ONLY one short sentence, be very technical.');
let question = "the future for riscv compared to arm";
*/

/*
ai.setRole('act as a vegan home cooker. do not use emojis');
ai2.setRole('act as a restaurant cooker. do not use emojis.');
let question = "let's invent a new recipe for a cake"; // the future for riscv compared to arm";
*/

ai.setRole('act as a vim user that never agree with emacs users. use a single short sentence and show turn up the attack.');
ai2.setRole('act as an emacs user. cannot agree with vim users. use a single short sentence.');
let question = "discuss about which is the best text editor";

for (let i = 0; i < 15; i++) {
	say('sam', question);
	let reply = ai.query (filter(question));
//	ai.reset();
	say('Matilda', reply);
	question = ai2.query(filter(reply));
//	ai2.reset();
}

})();
