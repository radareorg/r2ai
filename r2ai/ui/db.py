import dbm

db = dbm.open(".r2ai.db", "c")

def set_env(k, v):
    db[k] = v.encode('utf-8')  # Encode the value to bytes

def get_env(k):
    value = db.get(k)
    if value is None:
        return None
    return value.decode('utf-8')  # Decode bytes to string

def close_db():
    if db is not None:
        db.close()

# Ensure the database is closed when the module is unloaded
import atexit
atexit.register(close_db)

