from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, String, Text

from app.database.database import Base


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True, nullable=False)
    scanner_type = Column(String, index=True, nullable=False)
    risk_score = Column(Float, nullable=False, default=0)
    confidence_score = Column(Float, nullable=False, default=0)
    threat_level = Column(String, default="LOW RISK")
    status = Column(String, default="completed")
    summary = Column(Text, default="")
    findings = Column(Text, default="[]")
    recommendations = Column(Text, default="[]")
    raw_input = Column(Text, default="")
    report_data = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)
