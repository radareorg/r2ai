# MODEL="meta-llama/Llama-2.7b"
MODEL="Araeynn/llama2"
QUERY="The scale, variety, and quantity f publicly-available NLP datasets has grown rapidly as researchers propose new tasks, larger models, and novel benchmarks."

MODEL="bert-base-uncased"
QUERY="the result of 1 + 1 is [MASK]"
QUERY="1 + 1 = [MASK]"

# models https://huggingface.co/transformers/v3.3.1/pretrained_models.html
MODEL="gpt2"
#QUERY="explain what this function does: x=1+2"
API_TOKEN=""
MODEL="distilgpt2"
MODEL="gpt2-large"

# MODEL="ClassCat/gpt2-small-catalan-v2"
# MODEL="microsoft/codereviewer"
# MODEL="softcatala/wav2vec2-large-xlsr-catala"
# MODEL="jborras18/qa_bert_catalan"
QUERY="$1"


#curl -s "https://api-inference.huggingface.co/models/${MODEL}" \
#	--header "Authorization: Bearer ${API_TOKEN}" \
#        -X POST  -d "{\"wait_for_model\":true,\"max_length\":1000,\"use_cache\":false,\"inputs\": \"${QUERY}\"}" | jq -r .[0].generated_text

# exit 0

MODEL="deepset/roberta-base-squad2"
MODEL="google/tapas-base-finetuned-wtq"
MODEL="microsoft/DialoGPT-large"

curl -s "https://api-inference.huggingface.co/models/${MODEL}" \
	--header "Authorization: Bearer ${API_TOKEN}" \
        -X POST  -d "{\"past_user_inputs\":[\"you are a skilled radare user\"],\"text\":\"${QUERY}\"}" | jq .
