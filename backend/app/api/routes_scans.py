import json
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.scan import ScanRecord
from app.schemas.scan import EmailScanRequest, SMSScanRequest, WebsiteScanRequest
from app.services.ai_engine.ai_service import AIAnalysisService
from app.services.email_scanner.email_scanner import analyze_email
from app.services.reporting.report_generator import build_report_document
from app.services.sms_scanner.sms_scanner import analyze_sms
from app.services.website_scanner.website_scanner import analyze_website

router = APIRouter(prefix="/api")
AI_SERVICE = AIAnalysisService()


def serialize_scan(record: ScanRecord) -> dict:
    return {
        "scan_id": record.scan_id,
        "scanner_type": record.scanner_type,
        "risk_score": record.risk_score,
        "confidence_score": record.confidence_score,
        "threat_level": record.threat_level,
        "status": record.status,
        "summary": record.summary,
        "findings": json.loads(record.findings or "[]"),
        "recommendations": json.loads(record.recommendations or "[]"),
        "metadata": json.loads(record.report_data or "{}"),
        "raw_input": record.raw_input,
        "created_at": record.created_at.isoformat(),
    }


def save_scan(db: Session, scan_type: str, raw_input: str, analysis: dict) -> ScanRecord:
    scan_id = uuid.uuid4().hex
    record = ScanRecord(
        scan_id=scan_id,
        scanner_type=scan_type,
        risk_score=analysis["risk_score"],
        confidence_score=analysis["confidence_score"],
        threat_level=analysis["threat_level"],
        status=analysis["status"],
        summary=analysis["summary"],
        findings=json.dumps(analysis["findings"]),
        recommendations=json.dumps(analysis["recommendations"]),
        raw_input=raw_input,
        report_data=json.dumps(analysis["metadata"]),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("/health")
def health():
    return {"status": "ok", "message": "PhishGuard AI backend is running."}


@router.post("/scans/email")
async def email_scan(payload: EmailScanRequest, db: Session = Depends(get_db)):
    analysis = analyze_email(payload.email_text or "", payload.email_headers or "", payload.sender_id)
    ai_context = await AI_SERVICE.generate_explanation("email", analysis["findings"], analysis["risk_score"])
    analysis["ai_assessment"] = ai_context
    record = save_scan(db, "email", payload.email_text or payload.email_headers, analysis)
    return serialize_scan(record)


@router.post("/scans/website")
async def website_scan(payload: WebsiteScanRequest, db: Session = Depends(get_db)):
    analysis = analyze_website(payload.url)
    ai_context = await AI_SERVICE.generate_explanation("website", analysis["findings"], analysis["risk_score"])
    analysis["ai_assessment"] = ai_context
    record = save_scan(db, "website", payload.url, analysis)
    return serialize_scan(record)


@router.post("/scans/sms")
async def sms_scan(payload: SMSScanRequest, db: Session = Depends(get_db)):
    analysis = analyze_sms(payload.message, payload.sender_id, payload.extracted_url)
    ai_context = await AI_SERVICE.generate_explanation("sms", analysis["findings"], analysis["risk_score"])
    analysis["ai_assessment"] = ai_context
    record = save_scan(db, "sms", payload.message, analysis)
    return serialize_scan(record)


@router.get("/scans")
def list_scans(
    db: Session = Depends(get_db),
    search: str | None = Query(None),
    scanner_type: str | None = Query(None),
    risk_level: str | None = Query(None),
    page: int = 1,
    page_size: int = 20,
):
    query = db.query(ScanRecord)
    if search:
        query = query.filter(or_(ScanRecord.summary.ilike(f"%{search}%"), ScanRecord.raw_input.ilike(f"%{search}%")))
    if scanner_type:
        query = query.filter(ScanRecord.scanner_type == scanner_type)
    if risk_level:
        query = query.filter(ScanRecord.threat_level == risk_level)

    total = query.count()
    items = query.order_by(ScanRecord.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [serialize_scan(item) for item in items], "total": total, "page": page, "page_size": page_size}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return serialize_scan(scan)


@router.get("/scans/{scan_id}/report")
def get_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    report = {
        "scan_id": scan.scan_id,
        "scanner_type": scan.scanner_type,
        "risk_score": scan.risk_score,
        "confidence_score": scan.confidence_score,
        "threat_level": scan.threat_level,
        "summary": scan.summary,
        "findings": json.loads(scan.findings or "[]"),
        "recommendations": json.loads(scan.recommendations or "[]"),
        "metadata": json.loads(scan.report_data or "{}"),
        "created_at": scan.created_at.isoformat(),
    }
    return report


@router.get("/scans/{scan_id}/report/pdf")
def get_report_pdf(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    report_data = {
        "scan_id": scan.scan_id,
        "scanner_type": scan.scanner_type,
        "risk_score": float(scan.risk_score),
        "confidence_score": float(scan.confidence_score),
        "threat_level": scan.threat_level,
        "summary": scan.summary,
        "findings": json.loads(scan.findings or "[]"),
        "recommendations": json.loads(scan.recommendations or "[]"),
        "created_at": scan.created_at.isoformat(),
    }
    pdf_bytes = build_report_document(report_data)
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=phishguard-{scan_id}.pdf"})


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"status": "deleted", "scan_id": scan_id}
