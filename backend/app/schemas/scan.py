from datetime import datetime

from pydantic import BaseModel, Field


class ScanBase(BaseModel):
    scanner_type: str
    raw_input: str = ""
    metadata: dict | None = None


class EmailScanRequest(BaseModel):
    email_text: str = ""
    email_headers: str = ""
    sender_id: str | None = None


class WebsiteScanRequest(BaseModel):
    url: str


class SMSScanRequest(BaseModel):
    message: str
    sender_id: str | None = None
    extracted_url: str | None = None


class ScanResult(BaseModel):
    scan_id: str
    scanner_type: str
    risk_score: float
    confidence_score: float
    threat_level: str
    status: str
    summary: str
    findings: list[str]
    recommendations: list[str]
    metadata: dict
    created_at: datetime


class DashboardStats(BaseModel):
    total_scans: int
    safe_detections: int
    suspicious_detections: int
    phishing_detections: int
    average_risk_score: float
    detection_rate: float
