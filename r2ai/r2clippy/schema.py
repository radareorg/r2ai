from pydantic import BaseModel, ConfigDict, Field

class classproperty:
    def __init__(self, func):
        self.fget = func

    def __get__(self, instance, owner):
        return self.fget(owner)

class OpenAISchema(BaseModel):
    model_config = ConfigDict(ignored_types=(classproperty,))

    @classproperty
    def openai_schema(cls):
        schema = cls.model_json_schema()
        doc = cls.__doc__ or ""
        parameters = {k: v for k, v in schema.items(
        ) if k not in ("title", "description")}
        parameters["required"] = sorted(
            k for k, v in parameters["properties"].items() if "default" not in v)
        if "description" not in schema:
            schema["description"] = doc
        return {
            "name": schema["title"],
            "description": schema["description"],
            "parameters": parameters,
        }