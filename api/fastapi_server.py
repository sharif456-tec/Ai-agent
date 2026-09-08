from datetime import datetime
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import socket
import ssl

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

app = FastAPI(title="AI Security Command Center")

class ScanRequest(BaseModel):
    target: HttpUrl

_last_scan = None
_logs = []

SECURITY_HEADERS = {
    "Content-Security-Policy": "medium",
    "Strict-Transport-Security": "medium",
    "X-Frame-Options": "low",
    "X-Content-Type-Options": "low",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
}

def add_log(message, target=None):
    _logs.append({"time": datetime.utcnow().isoformat(), "message": message, "target": target})
    del _logs[:-50]

def passive_scan(target: str):
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only http/https URLs are supported")

    request = Request(target, headers={"User-Agent": "AI-Security-Auditor/1.0"}, method="GET")
    try:
        with urlopen(request, timeout=8) as response:
            headers = {k: v for k, v in response.headers.items()}
            status = response.status
            final_url = response.geturl()
    except Exception as exc:
        raise RuntimeError(f"Target could not be checked: {exc}")

    findings = []
    for name, severity in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append({"severity": severity, "title": f"Missing {name}", "type": "security-header"})

    if parsed.scheme != "https":
        findings.append({"severity": "high", "title": "Target is not using HTTPS", "type": "transport"})

    cookies = headers.get("Set-Cookie", "")
    if cookies and "Secure" not in cookies:
        findings.append({"severity": "medium", "title": "Cookie may be missing Secure attribute", "type": "cookie"})
    if cookies and "HttpOnly" not in cookies:
        findings.append({"severity": "medium", "title": "Cookie may be missing HttpOnly attribute", "type": "cookie"})

    technologies = []
    if headers.get("Server"):
        technologies.append("Server: " + headers["Server"])
    if headers.get("X-Powered-By"):
        technologies.append("X-Powered-By: " + headers["X-Powered-By"])

    critical = sum(f["severity"] == "critical" for f in findings)
    high = sum(f["severity"] == "high" for f in findings)
    medium = sum(f["severity"] == "medium" for f in findings)
    low = sum(f["severity"] == "low" for f in findings)
    score = max(0, 100 - critical * 30 - high * 15 - medium * 7 - low * 3)

    return {
        "target": target,
        "final_url": final_url,
        "http_status": status,
        "security_score": score,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "findings": findings,
        "technologies": technologies,
        "scanned_at": datetime.utcnow().isoformat(),
        "mode": "passive-safe-audit",
    }

@app.get('/api/health')
def health():
    return {"agent": "online", "time": datetime.utcnow().isoformat()}

@app.get('/api/logs')
def logs():
    return {"logs": _logs[-50:]}

@app.get('/api/last-scan')
def last_scan():
    return _last_scan or {"status": "not_started"}

@app.post('/api/scan')
def scan(request: ScanRequest):
    global _last_scan
    target = str(request.target)
    add_log("Passive security scan started", target)
    try:
        _last_scan = passive_scan(target)
    except Exception as exc:
        add_log("Scan failed: " + str(exc), target)
        raise HTTPException(status_code=400, detail=str(exc))
    add_log("Passive security scan completed", target)
    return _last_scan

@app.get('/api/ssl')
def ssl_check(host: str):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {"host": host, "tls": ssock.version(), "cipher": ssock.cipher()[0], "subject": cert.get("subject")}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
