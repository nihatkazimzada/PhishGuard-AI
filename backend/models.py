from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(80), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    api_calls_count = Column(Integer, default=0, nullable=False)

    scans = relationship("ScanResult", back_populates="owner", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    email_subject = Column(String(500), nullable=True)
    email_body = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False, default=0)
    verdict = Column(String(20), nullable=False, default="SUSPICIOUS")
    ai_explanation = Column(Text, nullable=True)
    indicators = Column(JSON, nullable=True)
    scanned_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    owner = relationship("User", back_populates="scans")
