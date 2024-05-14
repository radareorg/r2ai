import re
import random
import string

def get_random_tool_call_id():
    return "call_" + "".join(
        [random.choice(string.ascii_letters + string.digits) for _ in range(24)]
    )

def construct_tool_parameters_prompt(parameters):
    prompt = ""
    props = parameters["properties"]
    for name in props:
        parameter = props[name]
        prompt += (
            "<parameter>\n"
            f"<name>{name}</name>\n"
            f"<description>{parameter['description']}</description>\n"
            f"<type>{parameter['type']}</type>\n"
            "</parameter>\n"
        )
    return prompt

def construct_tool_prompt(func):
    tool = func['function']
    prompt = (
        "<tool_description>\n"
        f"<tool_name>{tool['name']}</tool_name>\n"
        "<description>\n"
        f"{tool['description']}\n"
        "</description>\n"
        "<parameters>\n"
        f"{construct_tool_parameters_prompt(tool['parameters'])}\n"
        "</parameters>\n"
        "</tool_description>"
    )
    return prompt

def construct_tool_use_system_prompt(tools):
    tool_use_system_prompt = (
        "In this environment you have access to a set of tools "
        "you can use to answer the user's question.\n\n"
        "You may call them like this:\n"
        "<function_calls>\n"
        "<invoke>\n"
        "<tool_name>$TOOL_NAME</tool_name>\n"
        "<parameters>\n"
        "<$PARAMETER_NAME>$PARAMETER_VALUE</$PARAMETER_NAME>\n"
        "...\n"
        "</parameters>\n"
        "</invoke>\n"
        "</function_calls>\n"
        "\n"
        "Here are the tools available:\n"
        "<tools>\n"
        + '\n'.join([construct_tool_prompt(tool) for tool in tools]) +
        "\n</tools>"
    )
    return tool_use_system_prompt

TAGS = r'<function_calls>|</function_calls>|<invoke>|</invoke>|<tool_name>|</tool_name>|<parameters>|</parameters>'

def parse_tags(invoke_string):
    tool_name = re.findall(r'<tool_name>.*?</tool_name>', invoke_string, re.DOTALL)
    if not tool_name:
        raise Exception("Missing <tool_name></tool_name> tags inside of <invoke></invoke> tags.")
    if len(tool_name) > 1:
        raise Exception("More than one tool_name specified inside single set of <invoke></invoke> tags.")

    parameters = re.findall(r'<parameters>.*?</parameters>', invoke_string, re.DOTALL)
    if not parameters:
        raise Exception("Missing <parameters></paraeters> tags inside of <invoke></invoke> tags.")
    if len(parameters) > 1:
        raise Exception("More than one set of <parameters></parameters> tags specified inside single set of <invoke></invoke> tags.")
    # Check for balanced tags inside parameters
    # TODO: This will fail if the parameter value contains <> pattern
    # TODO: or if there is a parameter called parameters. Fix that issue.
    tags = re.findall(r'<.*?>', parameters[0].replace('<parameters>', '').replace('</parameters>', ''), re.DOTALL)
    if len(tags) % 2 != 0:
        raise Exception("Imbalanced tags inside <parameters></parameters> tags.")
    return tool_name, parameters, tags

def _function_calls_valid_format_and_invoke_extraction(last_completion):
    """Check if the function call follows a valid format and extract the
       attempted function calls if so. Does not check if the tools actually
       exist or if they are called with the requisite params."""
    # Check if there are any of the relevant XML tags present that would
    # indicate an attempted function call.
    function_call_tags = re.findall(TAGS, last_completion, re.DOTALL)
    if not function_call_tags:
        # TODO: Should we return something in the text to claude indicating
        # that it did not do anything to indicate an attempted function call
        # (in case it was in fact trying to and we missed it)?
        return {"status": True, "invokes": []}
    # Extract content between <function_calls> tags. If there are multiple we
    # will only parse the first and ignore the rest, regardless of their correctness.
    match = re.search(r'<function_calls>(.*)</function_calls>', last_completion, re.DOTALL)
    if not match:
        return {"status": False, "reason": "No valid <function_calls></function_calls> tags present in your query."}
    func_calls = match.group(1)

    prefix_match = re.search(r'^(.*?)<function_calls>', last_completion, re.DOTALL)
    if prefix_match:
        func_call_prefix_content = prefix_match.group(1)
    # Check for invoke tags
    # TODO: Is this faster or slower than bundling with the next check?
    invoke_regex = r'<invoke>.*?</invoke>'
    if not re.search(invoke_regex, func_calls, re.DOTALL):
        return {"status": False, "reason": "Missing <invoke></invoke> tags inside of <function_calls></function_calls> tags."}
    # Check each invoke contains tool name and parameters
    invoke_strings = re.findall(invoke_regex, func_calls, re.DOTALL)
    invokes = []
    for invoke_string in invoke_strings:
        try:
            tool_name, parameters, tags = parse_tags(invoke_string)
        except Exception as e:
            return {"status": False, "reason": e}

        # Loop through the tags and check if each even-indexed tag matches the
        # tag in the position after it (with the / of course). If valid store
        # their content for later use.
        # TODO: Add a check to make sure there aren't duplicates provided of a given parameter.
        arguments = {}
        for i in range(0, len(tags), 2):
            opening_tag = tags[i]
            closing_tag = tags[i+1]
            closing_tag_without_second_char = closing_tag[:1] + closing_tag[2:]
            if closing_tag[1] != '/' or opening_tag != closing_tag_without_second_char:
                return {"status": False, "reason": "Non-matching opening and closing tags inside <parameters></parameters> tags."}
            arguments[opening_tag[1:-1]] = re.search(rf'{opening_tag}(.*?){closing_tag}', parameters[0], re.DOTALL).group(1)
        # Parse out the full function call
        invokes.append({
            "function": {
                "name": tool_name[0].replace('<tool_name>', '').replace('</tool_name>', ''),
                "arguments": arguments,
            },
            "id": get_random_tool_call_id()
        })
    return {"status": True, "invokes": invokes, "prefix_content": func_call_prefix_content}

def extract_claude_tool_calls(interpreter, stream):
    msg = ''
    res = None
    for event in stream:
        if event.type == "content_block_delta":
            delta = event.delta
            msg += delta.text
            res = _function_calls_valid_format_and_invoke_extraction(msg)
            if res["status"] is True and "invokes" in res and len(res["invokes"]) > 0:
                interpreter.messages.append({ "role": "assistant", "content": msg})
                return res["invokes"], res["prefix_content"]
    interpreter.messages.append({ "role": "assistant", "content": msg})
    return [], re.sub(r'<function_calls>.*</function_calls>', '', msg)
