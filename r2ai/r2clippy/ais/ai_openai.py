from openai import OpenAI

from ..decorators import context, system_message
from ..functions import get_ai_tools
from ..models import parse_model_str
from .processors import process_streaming_response


@system_message
@context
def chat(interpreter):
    call = True
    while call:
        if not interpreter.openai_client:
            interpreter.openai_client = OpenAI()

        client: OpenAI = interpreter.openai_client  # type hint for sanity
        client.base_url = interpreter.api_base
        model = parse_model_str(interpreter.model)
        try:
            response = client.chat.completions.create(
                model=model.id,
                max_tokens=int(interpreter.env["llm.maxtokens"]),
                tools=get_ai_tools(),
                messages=interpreter.messages,
                tool_choice="auto",
                stream=True,
                temperature=float(interpreter.env["llm.temperature"])
            )
            call = process_streaming_response(
                interpreter, response, max_retries=3)
        except:
            raise
    return response
