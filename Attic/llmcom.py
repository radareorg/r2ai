from transformers import AutoTokenizer
import transformers
import torch

model = "facebook/llm-compiler-13b"
model = "QuantFactory/llm-compiler-7b-GGUF"
# model = "file:///tmp/llm-compiler.gguf"

tokenizer = AutoTokenizer.from_pretrained(model)
pipeline = transformers.pipeline(
    "text-generation",
    model=model,
    torch_dtype=torch.float16,
    device_map="auto",
)

sequences = pipeline(
    '%3 = alloca i32, align 4',
    do_sample=True,
    top_k=10,
    temperature=0.1,
    top_p=0.95,
    num_return_sequences=1,
    eos_token_id=tokenizer.eos_token_id,
    max_length=200,
)
for seq in sequences:
    print(f"Result: {seq['generated_text']}")
