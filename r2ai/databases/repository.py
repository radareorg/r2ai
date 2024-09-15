from r2ai.databases.base_db import BaseDB
from typing import List
from flashrank import Ranker, RerankRequest

class DBRepository(BaseDB):
    def __init__(self) -> None:
        self.dbs: List[BaseDB] = []
    
    def add_db(self, *args):
        for db in args:
            if not isinstance(db, BaseDB):
                raise ValueError("Database object must be of type BaseDB")
            self.dbs.append(db)
    
    def save_memory(self, memory: str):
        for db in self.dbs:
            db.save_memory(memory)
    
    def load_memory(self, query):
        memories = []
        for db in self.dbs:
            memory = db.load_memory(query)
            if memory:
                memories.append(memory)
        return memory[0] if memory else None
    
    #TODO: Rank results from multiple databased and pick the one that matches the most
    def _get_best_memory(self):
        raise NotImplementedError()