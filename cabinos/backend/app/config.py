import os


class Settings:
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///./cabinos.db')
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
    MASTER_KEY = os.environ.get('MASTER_KEY', 'supersecret_master_key')
    MASTER_KEY_BYTES = MASTER_KEY.encode().ljust(32, b'0')[:32]
    SKEW_SECONDS = int(os.environ.get('SKEW_SECONDS', '120'))
    REPLAY_TTL_SECONDS = int(os.environ.get('REPLAY_TTL_SECONDS', '600'))
    RATE_WINDOW_SECONDS = int(os.environ.get('RATE_WINDOW_SECONDS', '60'))
    RATE_LIMIT_PER_WINDOW = int(os.environ.get('RATE_LIMIT_PER_WINDOW', '180'))
    TRUST_DECAY_PER_HOUR = float(os.environ.get('TRUST_DECAY_PER_HOUR', '0.25'))
    TRUST_UNQUARANTINE_AT = float(os.environ.get('TRUST_UNQUARANTINE_AT', '-10'))
    TRUST_QUARANTINE_BELOW = float(os.environ.get('TRUST_QUARANTINE_BELOW', '-20'))


settings = Settings()
