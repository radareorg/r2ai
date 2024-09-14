from queue import Queue
from typing import Dict, Tuple, Union

from r2ai.r2clippy.utils import split_string_with_limit

_chunks: Queue = Queue()


def add_chunk(text: str, max_tokens = 2000):
    global _chunks
    if _chunks.qsize() > 0:
        _chunks = Queue()
    if text.strip() == "":
        return 0
    for i in split_string_with_limit(text, max_tokens, "cl100k_base"):
        _chunks.put(i)
    return _chunks.qsize()

def get_chunk():
    global _chunks
    if _chunks.qsize() == 0:
        return str()
    return _chunks.get()

def size():
    global _chunks
    return _chunks.qsize()