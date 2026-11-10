import re
from urllib.parse import urlparse

from app.services.detection_engine.risk_engine import build_scan_result

SUSPICIOUS_EMAIL_PATTERNS = {
    "urgent action": "Urgent action language was detected.",
    "verify your account": "The message requests account verification.",
    "reset your password": "Password reset language can be used in phishing attempts.",
    "payout": "Payment-related urgency was detected.",
    "suspended": "Account suspension threat language was detected.",
    "invoice": "Invoice or payment manipulation language was found.",
    "click here": "A call-to-action button or link may be used to lure a victim.",
    "secure your account": "The message attempts to create a false sense of urgency.",
    "update your kyc": "KYC or compliance updates are often used in social-engineering scams.",
}


def analyze_email(email_text: str, email_headers: str = "", sender_id: str | None = None) -> dict:
    text = (email_text or "").strip()
    headers = (email_headers or "").strip()
    lower = text.lower()
    findings = []
    score = 10

    for phrase, reason in SUSPICIOUS_EMAIL_PATTERNS.items():
        if phrase in lower:
            findings.append(reason)
            score += 12

    if re.search(r"(?i)(verify|confirm|update|secure|suspend).*account|login|password", text):
        findings.append("Credential harvesting language was detected in the message body.")
        score += 16

    urls = re.findall(r"https?://[^\s>\"']+|www\.[^\s>\"']+", text + " " + headers)
    if urls:
        findings.append(f"{len(urls)} link reference(s) were found in the email body or headers.")
        score += 8
        for url in urls:
            parsed = urlparse(url if url.startswith(("http://", "https://")) else "https://" + url)
            if parsed.netloc and any(domain in parsed.netloc.lower() for domain in ["bit.ly", "tinyurl", "goo.gl", "t.co"]):
                findings.append("A URL shortener or redirect link was identified.")
                score += 12

    if any(term in lower for term in ["urgent", "immediately", "act now", "within 24 hours", "limited time"]):
        findings.append("Fear-based urgency language is present.")
        score += 10

    if re.search(r"(?i)(invoice|payment|wire transfer|gift card|bitcoin|crypto|bank account)", text):
        findings.append("The email contains financial fraud indicators.")
        score += 16

    if sender_id and sender_id.lower() not in lower.lower() and "noreply" not in (sender_id or "").lower() and "support" not in (sender_id or "").lower():
        findings.append("Sender display or from-address details do not match the message context.")
        score += 8

    if not text:
        findings.append("No message content was provided for analysis.")
        score = 5

    if "spf" in headers.lower() or "dkim" in headers.lower() or "dmarc" in headers.lower():
        findings.append("Authentication metadata was included in the email headers for review.")
        score += 5

    summary = "The message shows a moderate-to-high phishing pattern based on urgency, credential requests, and link behavior."
    if score < 25:
        summary = "The email appears to be legitimate based on the available text and metadata."
    elif score > 60:
        summary = "The email contains multiple indicators of phishing, impersonation, or credential theft attempts."

    recommendations = [
        "Verify the sender using a trusted channel before clicking any link.",
        "Check any URLs in a browser with anti-phishing controls enabled.",
        "Do not provide credentials, payment details, or MFA codes.",
        "Report the message to the organization’s security team if it appears suspicious."
    ]

    metadata = {
        "sender_id": sender_id,
        "url_count": len(urls),
        "auth_metadata_present": any(token in headers.lower() for token in ["spf", "dkim", "dmarc"]),
        "header_length": len(headers),
    }
    return build_scan_result("email", min(score, 100), findings or ["No obvious phishing indicators were identified."], recommendations, summary, metadata)
