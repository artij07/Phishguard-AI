from app.services.email_scanner.email_scanner import analyze_email
from app.services.sms_scanner.sms_scanner import analyze_sms
from app.services.website_scanner.website_scanner import analyze_website


def test_email_scan_detects_suspicious_patterns():
    result = analyze_email("Urgent action required. Verify your account immediately or your account will be suspended.")
    assert result["risk_score"] >= 60
    assert result["threat_level"] in {"HIGH RISK", "CRITICAL"}


def test_safe_sms_has_low_risk():
    result = analyze_sms("Hi team, the meeting starts at 4 PM tomorrow. Please bring your notes.")
    assert result["risk_score"] < 25


def test_website_scan_flags_login_obfuscation():
    result = analyze_website("https://secure-login-account-update-bank.com/?next=login")
    assert result["risk_score"] > 40
    assert any("phishing-style" in finding.lower() or "credential" in finding.lower() or "redirect" in finding.lower() for finding in result["findings"])
