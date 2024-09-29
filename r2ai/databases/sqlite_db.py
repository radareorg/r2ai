import sqlite3
import appdirs
import os

from flashrank import Ranker, RerankRequest
from r2ai.databases.base_db import BaseDB

class SqliteDB(BaseDB):
    def __init__(self, logger) -> None:
        self.logger = logger

        self.user_data_dir = appdirs.user_data_dir('r2ai')

        self.db_path = os.path.join(self.user_data_dir, 'memory.db')
        self.cur = self._setup_db(self.db_path)
        self.ranker = self._setup_fisherank()

        self.data: dict = self._load_all_memories()
    
    def load_memory(self, query):
        request = RerankRequest(query=query, passages=self.data)
        results = self.ranker.rerank(request)
        if (results):
            self.logger.getChild('auto.memory').info('Loaded memory: q: %s, m: %s, s: %s', query, results[0]['text'], results[0]['score'])
            return results[0]['text']
        else:
            return None

    def save_memory(self, memory: str):
        for d in self.data:
            if memory in d.items():
                return
        self.cur.execute('INSERT INTO memory ("summary") VALUES (?)', (memory,))
        self._commit()
        self.data.append({'id': len(self.data), 'text': memory})
        self.logger.getChild("auto.memory").info("Saved memory %s", memory)

    def _setup_db(self, path: str):
        self.db = sqlite3.connect(path)

        self.db.execute('CREATE TABLE IF NOT EXISTS memory(id INTEGER PRIMARY KEY AUTOINCREMENT, summary TEXT)')
        self._commit()
        return self.db.cursor()
    
    def _setup_fisherank(self, model=None):
        if model:
            return Ranker(model_name=model, cache_dir=self.user_data_dir)
        else:
            return Ranker(max_length=128)

    def _commit(self):
        self.db.commit()

    def _load_all_memories(self):
        data = []
        self.cur.execute('SELECT * FROM memory')
        rows = self.cur.fetchall()
        for row in rows:
            data.append({'id': row[0], 'text': row[1]})
        return data    