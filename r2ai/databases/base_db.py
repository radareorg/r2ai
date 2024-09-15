
class BaseDB:
    def __init__(self, logger) -> None:
        pass

    def load_memory(self, query):
        return None
    
    def save_memory(self, memory: str):
        pass