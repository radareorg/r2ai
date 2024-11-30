#!/bin/sh
OPENAI_KEY=""
OPENAI_MODEL="gpt-4"
if [ -f ~/.r2ai.openai-key ]; then
	OPENAI_KEY=$(cat ~/.r2ai.openai-key)
fi

openai() {
	INPUT=`(echo $@ ; cat) | jq -R -s . | sed 's/\*/\\*/g'`
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

openai "$@"
