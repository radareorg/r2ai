// Google Bard AI plugin for radare2
// author: pancake/nopcode.org
// TODO: this program requires bard-cli to be installed
// 1) go install github.com/mosajjal/bard-cli@latest
// 2) login in bard.google.com and take the cookie named: __Secure-1PSID
// 3) create ~/.bardcli.yaml and put ~/go/bin/bard-cli in $PATH
(function() {
 	// global settings
	const settings = {
		usePdc: true
	}
	function queryEsil(question) {
		if (question.indexOf('expression') !== -1) {
			const res = r2.cmd("aoeq");
			bard (question + res);
		} else if (question.indexOf('ranslate') !== -1) {
			const res = r2.cmd("piq 1 @e:scr.color=0");
			bard (question + ": " + res);
		} else {
			const res = r2.cmd("pdf @e:asm.bytes=0@e:asm.esil=true@e:scr.color=0");
			const message = question + ":\n```\n" + res + '\n```\n';
			bard (message);
		}
	}
	function queryProgram(question) {
		const res = r2.cmd("afs @@@F");
		const quote = (x) => `"${x}"`;
		if (res.length > 0) {
			let message = "";
			const fun = res[0];
			message += 'Considering a program with the following functions:\n```';
			message += res + '\n```\n';
			message += question;
			console.log(message);
			bard(message);
		} else {
			console.error ("No function found");
		}
	}
	function queryFunction(question) {
		const res = r2.cmdj("afij");
		const quote = (x) => `"${x}"`;
		if (res.length > 0) {
			let message = "";
			const fun = res[0];
			message += `The function have this signature '${fun.signature}'.\n`;
			const pdsf = r2.cmd("pdsf@e:scr.color=0");
			const imports = [];
			const strings = [];
			for (const line of pdsf.split(/\n/g)) {
				const words = line.split(/ /g);
				for (const word of words) {
					if (word.startsWith("sym.imp.")) {
						imports.push (word.slice(8));
					}
					if (word.startsWith("str.")) {
						strings.push (word.slice(4));
					}
				}
			}
			if (imports.length > 0) {
				message += " It is calling the following external functions: " + imports.join(', ') + ".\n";
			}
			if (strings.length > 0) {
				message += " And uses these strings: " + strings.map(quote).join(', ') + ".\n";
			}
			if (settings.usePdc || (imports.length === 0 && strings.length === 0)) {
				message += ' The pseudo code looks like:\n```c\n' + r2.cmd("pdc@e:scr.color=0") + '```';
			}
			message += question;
			bard(message);
		} else {
			console.error ("No function found");
		}
	}
	const actions = {
		"esil explain": "\nExplain the following ESIL expression: ",
		"esil decompile": "\nOptimize and give me a decompilation in python of the given function in ESIL",
		"esil generate": "\nTranslate the following instruction to ESIL",
		"fun name": "\nCan you give this function a better name?",
		"fun pseudo": "\nCan you provide a pseudocode in python?",
		"fun explain": "\nPlease, explain what this function is doing",
		"fun deco": "\nCan you optimize and decompile this function without including any introductory text?",
		"program frida-trace": "\nGive me a frida script to hook the write function and print the arguments passed.",
	};
	function bardAction(action) {
		if (action.startsWith ("query")) {
			bard(action.split(/ /g).slice(1).join(' '));
		} else if (action in actions) {
			const a = actions[action];
			if (action.startsWith ("esil")) {
				queryEsil(a);
			} else if (action.startsWith ("program")) {
				queryProgram(a);
			} else if (action.startsWith ("fun")) {
				queryFunction(a);
			} else {
				bard(a);
			}
		} else {
			console.error("Usage: bard [action]  # The following are supported:");
			console.error("- " + Object.keys(actions).join("\n- "));
			console.error("- query <your-message>");
		}
	}
	function bard(query) {
		// console.log(query);
		r2.cmd("p6ds "+ b64(query) + " > q.txt");
		// r2.call('!x="$(cat q.txt)"; bard-cli "$x"');
		r2.syscmd('x="$(cat q.txt)"; bard-cli "$x"');
		r2.call ("rm q.txt")
	}
	function bardCommand(input) {
		bardAction(input.slice(4).trim());
	}

	const registerPlugin = true; // set to false for experimenting
	if (registerPlugin) {
		function bardPlugin() {
			function coreCall(input) {
				if (input.startsWith("bard")) {
					bardCommand(input);
					return true;
				}
				return false;
			}
			return {
				name: "bard",
				desc: "Google Bard AI plugin for radare",
				call: coreCall,
			};
		}
		r2.plugin("core", bardPlugin);
	} else {
		bardAction("fun explain");
	}
})();
