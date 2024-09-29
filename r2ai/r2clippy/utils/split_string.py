import tiktoken

def split_string_with_limit(text, limit, encoding):
    if isinstance(encoding, str):
        encoding = tiktoken.get_encoding(encoding)
    tokens = encoding.encode(text)
    chunks = [tokens[i : i + limit] for i in range(0, len(tokens), limit)]
    return [encoding.decode(chunk) for chunk in chunks]