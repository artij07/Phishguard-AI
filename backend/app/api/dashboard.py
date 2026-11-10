import json
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.scan import ScanRecord

router = APIRouter(prefix="/api")


@router.get("/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    total_scans = db.query(ScanRecord).count()
    average_risk_score = db.query(func.avg(ScanRecord.risk_score)).scalar() or 0
    safe_detections = db.query(ScanRecord).filter(ScanRecord.threat_level == "LOW RISK").count()
    suspicious_detections = db.query(ScanRecord).filter(ScanRecord.threat_level == "SUSPICIOUS").count()
    phishing_detections = db.query(ScanRecord).filter(ScanRecord.threat_level.in_(["HIGH RISK", "CRITICAL"])) .count()

    detection_rate = 0.0
    if total_scans:
        detection_rate = round((phishing_detections / total_scans) * 100, 2)

    return {
        "total_scans": total_scans,
        "safe_detections": safe_detections,
        "suspicious_detections": suspicious_detections,
        "phishing_detections": phishing_detections,
        "average_risk_score": round(float(average_risk_score), 2),
        "detection_rate": detection_rate,
    }
