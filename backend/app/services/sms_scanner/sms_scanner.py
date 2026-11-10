import re

from app.services.detection_engine.risk_engine import build_scan_result

SMS_RISK_PATTERNS = {
    "urgent bank": "The message threatens account or banking problems.",
    "otp": "A one-time password request or verification code is being requested.",
    "suspend": "Account suspension language is being used to create urgency.",
    "verify": "The sender asks the recipient to verify account details.",
    "delivery": "Fake delivery or logistics prompt was detected.",
    "lottery": "Prize or lottery scam wording was identified.",
    "claim": "The message tries to entice a user with a reward claim.",
    "investment": "Investment or financial return language is present.",
    "loan": "Loan or credit scam language was detected.",
    "click": "The message urges a quick link click without context.",
}


def analyze_sms(message: str, sender_id: str | None = None, extracted_url: str | None = None) -> dict:
    text = (message or "").strip()
    lower = text.lower()
    findings = []
    score = 10

    if not text:
        findings.append("No message content was provided for analysis.")
        score = 5

    for phrase, reason in SMS_RISK_PATTERNS.items():
        if phrase in lower:
            findings.append(reason)
            score += 12

    if re.search(r"(?i)(urgent|immediately|today|within 30 minutes|final notice)", text):
        findings.append("High-pressure urgency language is present.")
        score += 12

    if re.search(r"(?i)(otp|one time password|code|mfa|2fa)", text):
        findings.append("The message requests a verification code or MFA passcode.")
        score += 16

    if re.search(r"(?i)(bank|financial|wallet|account|payment|kyc)", text):
        findings.append("Financial or account sensitivity language is present.")
        score += 10

    if extracted_url or ("http://" in text or "https://" in text):
        findings.append("A link is included in the message and should be inspected carefully.")
        score += 18

    if sender_id and sender_id.isdigit() and len(sender_id) < 10:
        findings.append("The sender identifier is short or unusual for a trusted commercial source.")
        score += 8

    if any(token in lower for token in ["claim your prize", "lottery", "winner", "bonus", "investment opportunity"]):
        findings.append("A scam reward or prize narrative was detected.")
        score += 14

    recommendations = [
        "Do not click or share the link in the SMS.",
        "Contact the organization using official channels before taking action.",
        "Do not share OTP, passwords, or payment information.",
        "Report any suspicious message to the appropriate reporting channel."
    ]

    summary = "The SMS appears to be a generic marketing message without a clear scam signal."
    if score >= 60:
        summary = "The SMS includes multiple common smishing indicators, including urgency, account language, and a suspicious link or request."
    elif score >= 25:
        summary = "The SMS contains some suspicious language and should be treated as cautionary until verified."

    metadata = {
        "sender_id": sender_id,
        "extracted_url": extracted_url,
        "message_length": len(text),
    }

    return build_scan_result("sms", min(score, 100), findings or ["No clear social-engineering patterns were identified."], recommendations, summary, metadata)
