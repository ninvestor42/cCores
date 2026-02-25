from sqlalchemy import Column, Integer, String, BigInteger, Text
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
