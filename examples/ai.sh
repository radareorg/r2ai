#!/bin/sh
OPENAPI_HOST=localhost
OPENAPI_PORT=8080

if [ -z "${OLLAMA_HOST}" ]; then
	OLLAMA_HOST=localhost
fi
if [ -z "${OLLAMA_PORT}" ]; then
	OLLAMA_PORT=11434
fi
if [ -z "${OLLAMA_MODEL}" ]; then
	OLLAMA_MODEL="llama3.2:1b"
fi

GEMINI_KEY=""
GEMINI_MODEL="gemini-1.5-flash"
if [ -f ~/.r2ai.gemini-key ]; then
	GEMINI_KEY=$(cat ~/.r2ai.gemini-key)
fi
OPENAI_KEY=""
OPENAI_MODEL="gpt-4o"
if [ -f ~/.r2ai.openai-key ]; then
	OPENAI_KEY=$(cat ~/.r2ai.openai-key)
fi
CLAUDE_KEY=""
CLAUDE_MODEL="claude-3-5-sonnet-20241022"
if [ -f ~/.r2ai.anthropic-key ]; then
	CLAUDE_KEY=$(cat ~/.r2ai.anthropic-key)
fi

SCISSORS="------------8<------------"

read_INPUT() {
	export INPUT=`(echo "$ARG" ; echo "<INPUT>"; cat ; echo "</INPUT>" ) | jq -R -s .`
		echo "$INPUT"
}

claude() {
	read_INPUT
	PAYLOAD="
	{
	\"model\": \"${CLAUDE_MODEL}\",
	\"max_tokens\": 5128,
	\"messages\": [ { \"role\": \"user\", \"content\": ${INPUT} } ]
	}
	"
	echo "$SCISSORS"
	curl -s https://api.anthropic.com/v1/messages \
		-H "Content-Type: application/json" \
		-H "anthropic-version: 2023-06-01" \
		-H "x-api-key: ${CLAUDE_KEY}" \
		-d "`printf '%s\n' \"${PAYLOAD}\"`" | jq -r '.content[0].text'
	echo "$SCISSORS"
}

ollama() {
	read_INPUT
	PAYLOAD="{ \"stream\":false, \"model\":\"${OLLAMA_MODEL}\", \"messages\": [{\"role\":\"user\", \"content\": ${INPUT} }]}"
	echo "$SCISSORS"
	curl -s "http://${OLLAMA_HOST}:${OLLAMA_PORT}/api/chat" \
		-H "Content-Type: application/json" \
		-d "`printf '%s\n' \"${PAYLOAD}\"`" | jq -r .message.content
	echo "$SCISSORS"
}

openapi() {
	read_INPUT
	PAYLOAD="{ \"prompt\": ${INPUT} }"
	echo "$SCISSORS"
	curl -s "http://${OPENAPI_HOST}:${OPENAPI_PORT}/completion" \
		-H "Content-Type: application/json" \
		-d "`printf '%s\n' \"${PAYLOAD}\"`" | jq -r .content
	echo "$SCISSORS"
}

openai() {
	read_INPUT
	PAYLOAD="
	{
	\"model\": \"${OPENAI_MODEL}\",
	\"max_completion_tokens\": 5128,
	\"messages\": [ { \"role\": \"user\", \"content\": ${INPUT} } ]
	}
	"
	echo "$SCISSORS"
	curl -s https://api.openai.com/v1/chat/completions \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer ${OPENAI_KEY}" \
		-d "`printf '%s\n' \"${PAYLOAD}\"`" | jq -r '.choices[0].message.content'
	echo "$SCISSORS"
}

gemini() {
	read_INPUT
	PAYLOAD=" {
	\"contents\":[{
          \"parts\":[
            {\"text\": ${INPUT}}
          ] }] }"
	echo "$SCISSORS"
	curl -s -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_KEY}" \
		-H "Content-Type: application/json" \
		-d "`printf '%s\n' \"${PAYLOAD}\"`" | jq -r .candidates[0].content.parts[0].text
	echo "$SCISSORS"
}

show_help() {
	cat <<EOF
$ ai [--] | [-h] | [prompt] < INPUT
-h = show this help message
-- = don't display the ---8<--- lines in the output
SHAI_API = ollama | gemini | claude | openai
OLLAMA_MODEL=hf.co/mradermacher/salamandra-7b-instruct-aina-hack-GGUF:salamandra-7b-instruct-aina-hack.Q4_K_M.gguf
OLLAMA_HOST=localhost
OLLAMA_PORT=11434
GEMINI_KEY=~/.r2ai-gemini.key
OPENAI_KEY=~/.r2ai-openai.key
CLAUDE_KEY=~/.r2ai-anthropic.key
CLAUDE_MODEL=claude-3-5-sonnet-20241022
EOF
	exit 0
}

[ "$1" = "-h" ] && show_help

if [ "$1" = "--" ]; then
	SCISSORS=""
	shift
fi

export ARG="$@"
case "${SHAI_API}" in
gemini|google) gemini ; ;;
openapi) openapi ; ;;
claude) claude ; ;;
ollama) ollama ; ;;
openai) openai ; ;;
*) claude ; ;;
esac
