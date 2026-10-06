import os
import shutil
from fmagenticl.server.storage_engine import StorageEngine

def test_sqlite_fallback():
    # Force SQLite test by not passing Redis URL
    test_db = "data/test_fmagenticl_kv.db"
    if os.path.exists(test_db):
        os.remove(test_db)
        
    engine = StorageEngine(db_path=test_db, redis_url="")
    
    assert engine.use_sqlite is True
    engine.set("key1", "val1")
    assert engine.exists("key1") is True
    assert engine.get("key1") == "val1"
    assert engine.dbsize() >= 1
    
    # Cleanup
    conn_dir = os.path.dirname(test_db)
    # Safely close/delete
    del engine
    
    # SQLite temp files might exist due to WAL
    for suffix in ["", "-wal", "-shm"]:
        path = test_db + suffix
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
