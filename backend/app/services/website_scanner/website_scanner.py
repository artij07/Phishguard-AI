import ipaddress
import re
from urllib.parse import urlparse

import httpx

from app.services.detection_engine.risk_engine import build_scan_result

BLOCKED_KEYWORDS = ["login", "verify", "account", "secure", "password", "update", "bank", "wallet"]
SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "tiny.cc"]


def is_private_or_local(host: str) -> bool:
    if not host:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        return False


def analyze_website(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    findings = []
    score = 10

    if parsed.scheme not in {"http", "https"}:
        findings.append("The submitted URL uses a non-HTTP(S) scheme and should be treated as suspicious.")
        score += 30

    if not parsed.netloc:
        findings.append("The URL format is invalid or incomplete.")
        score += 35
        return build_scan_result("website", min(score, 100), findings, ["Check the URL and re-run the analysis."], "The URL is malformed and cannot be safely assessed.", {"url": url})

    if host and is_private_or_local(host):
        findings.append("The target host resolves to a private or local network range, which is not safe to scan.")
        score += 40

    if any(keyword in host.lower() for keyword in ["verify", "secure", "update", "login", "account", "bank"]):
        findings.append("The hostname contains phishing-style words associated with credential harvesting.")
        score += 18

    if any(segment in host.lower() for segment in ["-verify", "-secure", "-login", "-support", "-update"]):
        findings.append("The domain structure suggests obfuscation or impersonation.")
        score += 14

    if any(token in url.lower() for token in ["?next=", "?redirect=", "?token=", "&email=", "&password="]):
        findings.append("The URL contains query parameters associated with redirect or credential collection flows.")
        score += 18

    if any(domain in host.lower() for domain in SHORTENER_DOMAINS):
        findings.append("A URL shortener is present in the domain name.")
        score += 22

    final_url = url
    status = "fetch_unavailable"
    redirected = False
    response_text = ""
    try:
        if host and not is_private_or_local(host):
            with httpx.Client(follow_redirects=False, timeout=10.0) as client:
                response = client.get(url, headers={"User-Agent": "PhishGuardAI/1.0"})
                status = f"HTTP {response.status_code}"
                final_url = str(response.url)
                redirected = response.history and len(response.history) > 0
                response_text = response.text[:15000]
                if response.status_code >= 300 and response.status_code < 400:
                    findings.append("The host issued an HTTP redirect. Redirect chains should be reviewed carefully.")
                    score += 12
                if "https" not in parsed.scheme.lower():
                    findings.append("The resource is being served over plain HTTP without TLS.")
                    score += 18
    except Exception:
        findings.append("The target could not be fetched safely; source verification is unavailable.")
        status = "fetch_failed"

    if response_text:
        if re.search(r"<form[^>]+method=[\"']?post[\"']?", response_text, re.I):
            findings.append("The page contains a form that may collect user credentials.")
            score += 20
        if re.search(r"<iframe|<script|src=\"https?://", response_text, re.I):
            findings.append("The page includes external script or iframe activity that can be abused in phishing pages.")
            score += 10
        if re.search(r"(?i)(password|email|username|login)", response_text):
            findings.append("The page content appears to contain login or credential collection elements.")
            score += 10

    if not findings:
        findings.append("No phishing indicators were identified from the current URL metadata.")

    recommendations = [
        "Check the domain reputation and confirm the brand identity before proceeding.",
        "Verify the site uses HTTPS and valid certificate information.",
        "Avoid entering credentials on pages that redirect unexpectedly or ask for sensitive information.",
        "Report suspicious domains to your security operations team."
    ]

    metadata = {
        "url": url,
        "host": host,
        "scheme": parsed.scheme,
        "redirected": redirected,
        "fetch_status": status,
        "final_url": final_url,
    }

    return build_scan_result("website", min(score, 100), findings, recommendations, "The domain and content profile suggest a mixed reputation and should be reviewed before login or downloads.", metadata)
