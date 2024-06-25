(function () {
	const command = "pdc-ai";
	const decprompt = 'make this pseudodisassembly more like a high level c decompilation, without gotos or confusing statements, do not introduce or explain the code, show only the code snippet';

	r2.unload("core", command);
	r2.plugin("core", function () {
		function r2ai(s) {
			const host = "http://localhost:8080/cmd";
			const ss = s.replace(/ /g, "%20"); 
			return r2.cmd ('!curl -s "' + host + '/' + ss + '"');
		}
		function coreCall(cmd) {
			if (cmd.startsWith(command)) {
				const args = cmd.slice(command.length);
				if (args === "") {
					console.error("Usage: " + command + " [args]");
				} else {
					r2.cmd ("pdc > /tmp/.pdc.txt");
					r2ai ("-R");
					r2ai ("-i /tmp/.pdc.txt " + decprompt);
				}
				return true;
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
