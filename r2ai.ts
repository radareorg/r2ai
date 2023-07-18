import { Configuration, OpenAIApi } from "openai";
const r2pipe = require ("r2pipe");
// import { open, r2node } from "r2pipe"; /// XXX we need types!

const useTTS = process.env.R2AI_TTS === '1';

const configuration = new Configuration({
    organization: "org-ges0Q9PvVCq5zJEpqwVgM6YC",
    apiKey: process.env.OPENAI_API_KEY,
});

type QuestionType = "identify" | "readcode";

function getQuestion(q: QuestionType) : string {
	switch (q) {
	case "identify":
		return "What open source project is this code from. Please only give me the program name and package name:";
	case "readcode":
		return "Can you explain what this decompiled function do?";
	}
}

async function main() {
	const openai = new OpenAIApi(configuration);
	try {
	const response = await openai.listEngines();
	var r2 = r2pipe.open()
	const input = getQuestion("readcode");
	const completion = await openai.createCompletion({
		model: "text-davinci-003",
		prompt: input + "```c\n" + r2.cmd("af;pdg") + "\n```\n",
	});
	console.log(completion.data.choices);
	const text = completion.data.choices[0].text;
	if (useTTS) {
		const filtered = text.replace(/[\n\*"]/, '');
		console.log(r2.cmd("\"?E " + text + "\""));
		r2.cmd("\"!say " + text + "\"");
	} else {
		console.log(text);
	}
	} catch (e) {
		console.log("Set your OPENAI API with the %OPENAI_API_KEY env var");
	}
}
main().then(function() {}).catch(function(err) {
	console.error(err.toString());
});
