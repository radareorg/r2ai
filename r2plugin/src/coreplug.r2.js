(function () {
	const command = "pdc-ai";
	let decprompt = "optimize this pseudodisasm into high level quality decompiled code,";
	decprompt += "replace goto with proper control flow statements,";
	decprompt += "use better names for variables,";
	decprompt += "show only the code snippet,";
	decprompt += "do not introduce or explain the code,";
	decprompt += "combine the compare line with the conditional line below,";
	decprompt += "use better names for variables. combine the compare line with the conditional line below,";
	decprompt += "keep comments from source";
	decprompt += "remove unnecessary assignments inlining them into the function argument calls, add a comment on top explaining whats the function for in one sentence";

	function usage() {
		console.error("Usage: " + command + " (-h) [prompt]");
		console.error(" " + command + " -d  - another decompile method");
		console.error(" " + command + " -d  - decompile");
		console.error(" " + command + " -e  - explain");
		console.error(" " + command + " -n  - suggest better function name");
		console.error(" " + command + " -v  - show local variables");
		console.error(" " + command + " -V  - find vulnerabilities");
	}
	function r2ai(s) {
		const host = "http://localhost:8080/cmd";
		const ss = s.replace(/ /g, "%20").replace(/'/g, "\\'");
		return r2.cmd ('!curl -s "' + host + '/' + ss + '"');
	}
	function r2aidec(args) {
		if (args === "") {
			usage ();
		} else if (args[0] === "-") {
			switch (args[1]) {
			case "n": // "-n"
			case "f": // "-f"
				r2.cmd ("pdc > /tmp/.pdc.txt");
				var considerations = r2.cmd("fd.").trim().split(/\n/).filter(x=>!x.startsWith("secti")).join(",");
				// console.log(considerations);
				r2ai ("-R");
				r2ai ("-i /tmp/.pdc.txt give me a better name for this function. the output must be: 'afn NEWNAME'. consider: " + considerations);
				break;
			case "v": // "-v"
				r2.cmd ("pdc > /tmp/.pdc.txt");
				r2ai ("-R");
				r2ai ("-i /tmp/.pdc.txt show only the local variables.");
				break;
			case "V": // "-V"
				r2aidec("-d find vulnerabilities, dont show the code, only show the response");
				break;
			case "e": // "-e"
				r2.cmd ("pdsf > /tmp/.pdc.txt");
				r2ai ("-R");
				r2ai ("-i /tmp/.pdc.txt Explain what's this function doing in one sentence.")
				break;
			case "D": // "-D"
				try {
					args = args.slice(2).trim();
					r2.cmd("'!echo 'Consider:\\n <code>' > /tmp/.pdc.txt");
					r2.cmd("pdc >> /tmp/.pdc.txt");
					// r2.cmd ("'!cat /tmp/.pdc.txt0 >> /tmp/.pdc.txt");
					r2.cmd("'!echo '</code>\\n and :\\n<code>' >> /tmp/.pdc.txt");
					r2.cmd("pdg >> /tmp/.pdc.txt");
					r2.cmd("'!echo '</code>\\n and :\\n<code>' >> /tmp/.pdc.txt");
					r2.cmd("pdd >> /tmp/.pdc.txt");
					r2.cmd("'!echo '</code>' >> /tmp/.pdc.txt");
					r2ai("-R");
					const p = decprompt + ". replace variables with the actual strings";
					r2ai("-i /tmp/.pdc.txt " + (p + " " + args).trim());
				} catch (e) {
					console.error(e);
				}
				break;
			case "d": // "-d"
				try {
					args = args.slice(2).trim();
					r2.cmd ("pdc > /tmp/.pdc.txt");
					r2ai("-R");
					r2ai("-i /tmp/.pdc.txt " + (decprompt + " " + args).trim());
				} catch (e) {
					console.error(e);
				}
				break;
			default:
				usage();
				break;
			}
		} else {
			console.log("ARGS: " + args);
			usage();
		}
		return true;
	}
	r2.unload("core", command);
	r2.plugin("core", function () {
		function coreCall(cmd) {
			if (cmd.startsWith(command)) {
				var args = cmd.slice(command.length).trim();
				return r2aidec(args);
			}
			return false;
		}
		return {
			"name": command,
			"license": "MIT",
			"desc": "r2 decompiler based on r2ai",
			"call": coreCall,
		};
	});
})();
