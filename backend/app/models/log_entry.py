from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True)
    log_file_id = Column(Integer, ForeignKey("log_files.id"), nullable=False, index=True)

    timestamp = Column(DateTime(timezone=True), index=True)
    cip = Column(String(45), index=True)  # client IP (v4/v6)
    login = Column(String(255))
    url = Column(Text)
    action = Column(String(20))
    urlcat = Column(String(100))
    threatname = Column(String(255))
    respcode = Column(String(10))
    reqmethod = Column(String(10))
    reqsize = Column(Integer)
    respsize = Column(Integer)
    malwarecat = Column(String(100))
    riskscore = Column(Integer)
    raw_line = Column(Text)

    log_file = relationship("LogFile", back_populates="entries")
    anomalies = relationship("Anomaly", back_populates="log_entry", cascade="all, delete-orphan")
