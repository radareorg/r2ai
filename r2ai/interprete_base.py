import logging
from typing import Any, List, Dict

class BaseInterpreter:
        logger: logging.Logger
        mistral: Any
        messages: List[Any]
        terminator: str
        api_key: Any
        print: Any
        auto_run: bool
        model: str
        last_model: str
        env: Dict[str, Any]
        openai_client: Any
        anthropic_client: Any
        groq_client: Any
        google_client: Any
        google_chat: Any
        bedrock_client: Any
        api_base: str
        system_message: str
        active_block: Any
        llama_instance: Any
        large: Any