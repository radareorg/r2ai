from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..anthropic import construct_tool_parameters_prompt
from . import constants
from .functions import get_ai_tools


# Use dataclasses maybe, to customize each modeel?
class Model(Enum):
    MEETKAY = 0
    ANTHROPIC = 1
    DEFAULT = 2


@dataclass
class Metadata:
    platform: str
    id: str
    uri: str


@dataclass
class Meetkai:
    system_prompt: str


@dataclass
class Anthropic:
    system_prompt: str


@dataclass
class Default:
    system_prompt: str


def get_model(model: Model) -> str:
    if model == Model.MEETKAY:
        return Meetkai(system_prompt=f"{constants.SYSTEM_PROMPT_AUTO}\n{constants.FUNCTIONARY_PROMPT_AUTO}")
    if model == Model.ANTHROPIC:
        return Anthropic(system_prompt=f"{constants.SYSTEM_PROMPT_AUTO}\n{construct_tool_parameters_prompt(get_ai_tools)}")
    return Default(system_prompt=constants.SYSTEM_PROMPT_AUTO)


def get_model_by_str(model: str) -> str:
    _model = Model.DEFAULT
    if model.startswith("meetkai/"):
        _model = Model.MEETKAY
    if model.startswith("anthropic"):
        _model = Model.ANTHROPIC
    return get_model(_model)


def parse_model_str(model: str) -> Optional[Metadata]:
    platform = ""
    id = ""
    uri = ""
    if ":" in model:
        slices = model.split(":")
        if len(slices) > 2:
            platform = slices[0]
            uri = ":".join(slices[:3][-2:])
            id = slices[3:]
            if len(model) > 1:
                id = ":".join(id)
        else:
            platform = model.split(":")[0]
            id = ":".join(model.split(":")[1:])
    elif "/" in model:
        return Metadata(
            platform=model.split("/")[0],
            id="/".join(model.split("/")[1:]),
            uri=uri  # ??
        )
    if all(x == "" for x in [platform, id, uri]):
        return None
    return Metadata(
        platform=platform,
        id=id,
        uri=uri,
    )
