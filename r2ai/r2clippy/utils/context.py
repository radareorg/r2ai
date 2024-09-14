from r2ai import index


def context_from_msg(msg: dict):
    keywords = None
    datadir = "doc/auto"
    use_vectordb = False
    last_msg = None
    content = msg.get("content")
    if isinstance(content, str):
        last_msg = msg["content"]
    if isinstance(content, list):
        last_msg = ". ".join([c["text"] for c in content if "text" in c])
    if not last_msg:
        return None
    matches = index.match(last_msg, keywords, datadir,
                          False, False, False, False, use_vectordb)
    if not matches:
        return None
    return "context: " + ", ".join(matches)