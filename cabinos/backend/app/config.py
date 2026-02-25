import os
class Settings:
    DATABASE_URL=os.environ.get('DATABASE_URL')
    REDIS_URL=os.environ.get('REDIS_URL')
    MASTER_KEY=os.environ.get('MASTER_KEY','supersecret_master_key')
    MASTER_KEY_BYTES=(MASTER_KEY.encode().ljust(32,b'0')[:32])
settings=Settings()
