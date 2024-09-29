from typing import Iterable, Callable

class R2AiEnv(dict):
    def __init__(self):
        self._callbacks = {}
        
    def add_callback(self, key: str, callback: Callable):
        self._callbacks[key] = callback
        
    def __setitem__(self, __key, __value) -> None:
        if __key in self._callbacks:
            self._callbacks[__key](__value)
        return super().__setitem__(__key, __value)