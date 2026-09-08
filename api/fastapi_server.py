from datetime import datetime
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import ipaddress
import socket
import ssl
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl

BASE_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = BASE_DIR / "dashboard" / "cloudflare-command-center"

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

def public_host(hostname: str) -> bool:
    try:
        if not hostname or hostname.lower() in {"localhost", "localhost.localdomain"}:
            return False
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_global
        except ValueError:
            pass
        addresses = {x[4][0] for x in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
        return bool(addresses) and all(ipaddress.ip_address(a).is_global for a in addresses)
    except Exception:
        return False

def passive_scan(target: str):
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only http/https website URLs are allowed")
    request = Request(target, headers={"User-Agent": "AI-Security-Auditor/1.0"}, method="GET")
    try:
        with urlopen(request, timeout=8) as response:
            headers = {k: v for k, v in response.headers.items()}
            status = response.status
            final_url = response.geturl()
    except Exception as exc:
        raise RuntimeError(f"Target could not be checked: {exc}")
    final = urlparse(final_url)
    if not final.hostname or final.scheme not in {"http", "https"} or not public_host(final.hostname):
        raise RuntimeError("Redirected to a private or reserved destination")
    findings = [{"severity": sev, "title": f"Missing {name}", "type": "security-header"} for name, sev in SECURITY_HEADERS.items() if name not in headers]
    if final.scheme != "https":
        findings.append({"severity": "high", "title": "Target is not using HTTPS", "type": "transport"})
    cookies = headers.get("Set-Cookie", "")
    if cookies and "Secure" not in cookies: findings.append({"severity": "medium", "title": "Cookie may be missing Secure attribute", "type": "cookie"})
    if cookies and "HttpOnly" not in cookies: findings.append({"severity": "medium", "title": "Cookie may be missing HttpOnly attribute", "type": "cookie"})
    technologies = []
    if headers.get("Server"): technologies.append("Server: " + headers["Server"])
    if headers.get("X-Powered-By"): technologies.append("X-Powered-By: " + headers["X-Powered-By"])
    counts = {s: sum(f["severity"] == s for f in findings) for s in ("critical", "high", "medium", "low")}
    return {"target": target, "final_url": final_url, "http_status": status, "security_score": max(0, 100-counts["critical"]*30-counts["high"]*15-counts["medium"]*7-counts["low"]*3), **counts, "findings": findings, "technologies": technologies, "scanned_at": datetime.utcnow().isoformat(), "mode": "passive-safe-audit"}

@app.get('/api/health')
def health(): return {"agent": "online", "time": datetime.utcnow().isoformat()}
@app.get('/api/logs')
def logs(): return {"logs": _logs[-50:]}
@app.get('/api/last-scan')
def last_scan(): return _last_scan or {"status": "not_started"}
@app.post('/api/scan')
def scan(request: ScanRequest):
    global _last_scan
    target = str(request.target); add_log("Passive security scan started", target)
    try: _last_scan = passive_scan(target)
    except Exception as exc:
        add_log("Scan failed: " + str(exc), target); raise HTTPException(status_code=400, detail=str(exc))
    add_log("Passive security scan completed", target); return _last_scan
@app.get('/api/ssl')
def ssl_check(host: str):
    if not public_host(host): raise HTTPException(status_code=400, detail="Private or reserved hosts are not allowed")
    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as ssock:
                return {"host": host, "tls": ssock.version(), "cipher": ssock.cipher()[0], "subject": ssock.getpeercert().get("subject")}
    except Exception as exc: raise HTTPException(status_code=400, detail=str(exc))

if DASHBOARD_DIR.exists():
    app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")
