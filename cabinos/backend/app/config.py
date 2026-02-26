import hashlib
import os


class Settings:
    def __init__(self) -> None:
        self.DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./cabinos.db")
        self.REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
        self.MASTER_KEY = os.environ.get("MASTER_KEY", "supersecret_master_key")
        self.MASTER_KEY_BYTES = hashlib.sha256(self.MASTER_KEY.encode("utf-8")).digest()


settings = Settings()
