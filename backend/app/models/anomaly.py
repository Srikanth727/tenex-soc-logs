from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True)
    log_entry_id = Column(Integer, ForeignKey("log_entries.id"), nullable=False, index=True)

    rule_name = Column(String(100), nullable=False)
    mitre_tag = Column(String(20))
    confidence_score = Column(Float)
    explanation = Column(Text)
    severity = Column(String(20))  # low, medium, high, critical
    status = Column(String(20), nullable=False, default="new")  # new, reviewed, dismissed
    detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    log_entry = relationship("LogEntry", back_populates="anomalies")
