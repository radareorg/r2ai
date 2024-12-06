#!/bin/sh
OPENAPI_HOST=localhost
OPENAPI_PORT=8080

GEMINI_KEY=""
GEMINI_MODEL="gpt-4"
if [ -f ~/.r2ai.gemini-key ]; then
	GEMINI_KEY=$(cat ~/.r2ai.gemini-key)
fi
OPENAI_KEY=""
OPENAI_MODEL="gpt-4"
if [ -f ~/.r2ai.openai-key ]; then
	OPENAI_KEY=$(cat ~/.r2ai.openai-key)
fi
CLAUDE_KEY=""
CLAUDE_MODEL="claude-3-5-sonnet-20241022"
if [ -f ~/.r2ai.anthropic-key ]; then
	CLAUDE_KEY=$(cat ~/.r2ai.anthropic-key)
fi

claude() {
	INPUT=`(echo "$@" ; cat) | jq -R -s . | sed 's/\*/\\*/g'`
	PAYLOAD="
	{
	\"model\": \"${CLAUDE_MODEL}\",
	\"max_tokens\": 5128,
	\"messages\": [ { \"role\": \"user\", \"content\": ${INPUT} } ]
	}
	"
	echo "------------8<------------"
	curl -s https://api.anthropic.com/v1/messages \
		-H "Content-Type: application/json" \
		-H "anthropic-version: 2023-06-01" \
		-H "x-api-key: ${CLAUDE_KEY}" \
		-d "`printf '%s\n' \"${PAYLOAD}\"`" | jq -r '.content[0].text'
	echo "------------8<------------"
}

openapi() {
	INPUT=`(echo "$1" ; cat) | jq -R -s . | sed 's/\*/\\*/g'`
	PAYLOAD="{ \"prompt\": ${INPUT} }"
	echo "------------8<------------"
	curl -s "http://${OPENAPI_HOST}:${OPENAPI_PORT}/api/generate" \
		-H "Content-Type: application/json" \
		-d "`printf '%s\n' \"${PAYLOAD}\"`" | jq -r .response
	echo "------------8<------------"
}

openai() {
	INPUT=`(echo "$@" ; cat) | jq -R -s . | sed 's/\*/\\*/g'`
	PAYLOAD="
	{
	\"model\": \"${OPENAI_MODEL}\",
	\"max_completion_tokens\": 5128,
	\"messages\": [ { \"role\": \"user\", \"content\": ${INPUT} } ]
	}
	"
	echo "------------8<------------"
	curl -s https://api.openai.com/v1/chat/completions \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer ${OPENAI_KEY}" \
		-d "`printf '%s\n' \"${PAYLOAD}\"`" | jq -r '.choices[0].message.content'
	echo "------------8<------------"
}

gemini() {
	INPUT=`(echo "$@" ; cat) | jq -R -s . | sed 's/\*/\\*/g'`
	PAYLOAD=" {
	\"contents\":[{
          \"parts\":[
            {\"text\": ${INPUT}}
          ] }] }"
	echo "------------8<------------"

	curl -s -X POST "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_KEY}" \
		-H "Content-Type: application/json" \
		-d "`printf '%s\n' \"${PAYLOAD}\"`" | jq -r .candidates[0].content.parts[0].text
	echo "------------8<------------"
}

case "${SHAI_API}" in
gemini|google) gemini "$@" ; ;;
openapi) openapi "$@" ; ;;
claude) claude "$@" ; ;;
openai) openai "$@" ; ;;
*) claude "$@" ; ;;
esac
