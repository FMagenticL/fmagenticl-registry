import os
from typing import Optional

class Settings:
    DB_PATH: str = os.getenv("FMAGENTICL_DB_PATH", "data/fmagenticl_kv.db")
    REDIS_URL: Optional[str] = os.getenv("REDIS_URL", None)

settings = Settings()
