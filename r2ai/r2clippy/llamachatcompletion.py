# from openai.types.chat import ChatCompletion


# class LlamaChatCompletion(ChatCompletion):
#     @classmethod
#     def from_llama_response(llamaResponse: dict) -> ChatCompletion:
#         choice = llamaResponse["choices"][0]
#         if "message" in choice:
#             if "content" in choice["message"]:
