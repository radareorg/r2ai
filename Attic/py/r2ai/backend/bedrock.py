from colorama import Fore, Back, Style

from ..pipe import get_r2_inst

BEDROCK_TOOLS_CONFIG = {
    "tools": [
        {
            "toolSpec": {
                "name": "r2cmd",
                "description": "runs commands in radare2. You can run it multiple times or chain commands with pipes/semicolons. You can also use r2 interpreters to run scripts using the `#`, '#!', etc. commands. The output could be long, so try to use filters if possible or limit. This is your preferred tool",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "command to run in radare2."
                            }
                        },
                        "required": [
                            "command"
                        ]
                    }
                }
            }
        }
    ]
}

def build_messages_for_bedrock(messages):
    # Bedrock needs that conversation messages alternate between user and assistant
    # if the user wants to send multiple messages they should all be consolidated
    # in a single entry

    bedrock_msgs = []
    for msg in messages:
        role = msg.get("role")
        if msg.get("role") not in ["user", "assistant"]:
            continue

        if len(bedrock_msgs) > 0 and bedrock_msgs[-1]["role"] == role:
            last_msg = bedrock_msgs[-1]
            # This message should be consolidated with the previous one
            if isinstance(msg["content"], list):
                last_msg["content"].extend(msg["content"])
            else:
                last_msg["content"].append({
                    "text": msg["content"]
                })

        else:
            # The role changed, so create a new entry
            if isinstance(msg["content"], list) and "role" in msg:
                # This clause is for messages that are returned from bedrock
                # and thus are already well formatted
                bedrock_msgs.append(msg)
            else:
                bedrock_msgs.append({
                    "role": role,
                    "content": [{"text": msg["content"]}]
                })

    return bedrock_msgs

def extract_bedrock_tool_calls(response):
    tool_calls = []
    content = response.get("output", {}).get("message", {}).get("content", [])
    for msg in content:
        if not "toolUse" in msg:
            continue

        tool_calls.append(msg["toolUse"])

    return tool_calls

def process_bedrock_tool_calls(calls):
    r2 = get_r2_inst()
    messages = []
    if not r2:
        print("Invalid r2 instance. Can not execute commands. Did you open a file?")
        return messages

    for call in calls:
        if call["name"] == "r2cmd":
            cmd = call["input"]["command"]
            print(f"\n{Fore.GREEN}Executing r2 cmd: {cmd}{Style.RESET_ALL}")
            res = r2.cmd(cmd)
            # print(f"{res}")
            messages.append({
                "role": "user",
                "content": [{
                    "toolResult": {
                        "toolUseId": call.get("toolUseId"),
                        "content": [{ "text": res }]
                    }
                }]
            })

    return messages

def print_bedrock_response(response, print=print, output_limit=200):
    msg = response.get("output", {}).get("message", {})
    
    for m in msg.get("content", []):
        if "text" in m:
            print(f"\n{Fore.YELLOW}[AI]> {Style.RESET_ALL}{m['text']}")
