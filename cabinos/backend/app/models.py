from sqlalchemy import Column,Integer,String,BigInteger,Text,Float,UniqueConstraint
from app.database import Base
class Identity(Base):
    __tablename__='identities'
    id=Column(Integer, primary_key=True, index=True)
    did=Column(String(80), unique=True, index=True, nullable=False)
    public_key=Column(String(128), unique=True, nullable=False)
    encrypted_private_key=Column(Text, nullable=False)
class AuditEvent(Base):
    __tablename__='audit_events'
    id=Column(Integer, primary_key=True, index=True)
    ts=Column(BigInteger, nullable=False)
    action=Column(Text, nullable=False)
    prev_hash=Column(String(64), nullable=False)
    chain_hash=Column(String(64), nullable=False)
    signer_key_id=Column(String(40), nullable=False, default='active')
    sig=Column(Text, nullable=False)
class DaemonToken(Base):
    __tablename__='daemon_tokens'
    id=Column(Integer, primary_key=True, index=True)
    name=Column(String(80), unique=True, index=True, nullable=False)
    token_hash=Column(String(64), unique=True, index=True, nullable=False)
class Peer(Base):
    __tablename__='peers'
    did=Column(String(80), primary_key=True)
    trust=Column(Float, nullable=False, default=0.0)
    status=Column(String(20), nullable=False, default='active')
    last_seen_ts=Column(BigInteger, nullable=False, default=0)
class AuditKey(Base):
    __tablename__='audit_keys'
    id=Column(Integer, primary_key=True, index=True)
    key_id=Column(String(40), unique=True, index=True, nullable=False)
    public_key=Column(String(128), unique=True, nullable=False)
    encrypted_private_key=Column(Text, nullable=False)
    is_active=Column(Integer, nullable=False, default=0)
class ReplayNonce(Base):
    __tablename__='replay_nonces'
    id=Column(Integer, primary_key=True, index=True)
    did=Column(String(80), nullable=False)
    nonce=Column(String(160), nullable=False)
    ts=Column(BigInteger, nullable=False)
    __table_args__=(UniqueConstraint('did','nonce',name='uq_replay_did_nonce'),)
