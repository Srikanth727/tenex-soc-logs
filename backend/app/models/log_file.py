from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base


class LogFile(Base):
    __tablename__ = "log_files"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False, default="processing")  # processing, complete, failed
    uploaded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    line_count = Column(Integer, default=0)

    entries = relationship("LogEntry", back_populates="log_file", cascade="all, delete-orphan")
