(function() {
 	const dir = r2.cmd("%SRCDIR").trim();
	if (dir === "") {
		console.error("Environment %SRCDIR not defined");
		return;
	}
	const ai = new R2AI()
	ai.setRole("You are developer writing documentation for Frida scripts to be read by users. Your explanation shouldn't be longer than one paragraphs");
	// console.log(ai.query("Hello World"))
	const files = r2.callj("ls -j " + dir);
	const listing = files.map ((x) => x.name).filter((x) => x.endsWith('.ts')).map((x) => dir + '/' + x);
	for (let fileName of listing) {
		const desc = ai.queryFile(fileName, "explain in few words what's this probe doing").split(/\n/)[0];
		console.log(fileName + ":\n    " + desc);
	}
})();
