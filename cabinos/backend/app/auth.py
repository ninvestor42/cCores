import time
from fastapi import Header, HTTPException
from app.crypto import sha256_hex
from app.database import SessionLocal
from app.models import DaemonToken
from app.redis_client import r
from app.config import settings

def require_daemon_token(x_daemon_token: str = Header(default='')):
    if not x_daemon_token: raise HTTPException(401,'missing X-DAEMON-TOKEN')
    h=sha256_hex(x_daemon_token)
    db=SessionLocal()
    try:
        row=db.query(DaemonToken).filter(DaemonToken.token_hash==h).first()
        if not row: raise HTTPException(401,'invalid daemon token')
        now=int(time.time()); window=now//settings.RATE_WINDOW_SECONDS
        key=f'rl:{h}:{window}'
        n=r.incr(key)
        if n==1: r.expire(key, settings.RATE_WINDOW_SECONDS+2)
        if n>settings.RATE_LIMIT_PER_WINDOW: raise HTTPException(429,'rate limit exceeded')
        return {'daemon_name':row.name,'token_hash':h}
    finally:
        db.close()
