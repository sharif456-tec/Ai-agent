from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import ipaddress
import socket
import ssl
import re

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

app = FastAPI(title="AI Security Command Center", version="2.0")

class ScanRequest(BaseModel):
    target: HttpUrl

_last_scan = None
_logs = []

SECURITY_HEADERS = {
    "Content-Security-Policy": ("medium", "Restricts script and resource sources."),
    "Strict-Transport-Security": ("medium", "Makes HTTPS the preferred transport."),
    "X-Frame-Options": ("low", "Helps reduce clickjacking exposure."),
    "X-Content-Type-Options": ("low", "Prevents MIME-type sniffing."),
    "Referrer-Policy": ("low", "Controls referrer information sent to other origins."),
    "Permissions-Policy": ("low", "Limits browser features exposed to the page."),
}

SECURITY_RECOMMENDATIONS = {
    "Content-Security-Policy": "Add a restrictive CSP appropriate for the application.",
    "Strict-Transport-Security": "Add HSTS after confirming HTTPS works correctly.",
    "X-Frame-Options": "Set DENY or SAMEORIGIN where framing is not required.",
    "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff.",
    "Referrer-Policy": "Use a deliberate policy such as strict-origin-when-cross-origin.",
    "Permissions-Policy": "Define a restrictive policy for unused browser features.",
}

def now():
    return datetime.now(timezone.utc).isoformat()

def add_log(message, target=None):
    _logs.append({"time": now(), "message": message, "target": target})
    del _logs[:-100]

def public_host(hostname: str) -> bool:
    try:
        host = hostname.rstrip(".").lower()
        if not host or host in {"localhost", "localhost.localdomain"} or host.endswith((".local", ".internal", ".localhost")):
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            pass
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = {x[4][0] for x in infos}
        return bool(addresses) and all(ipaddress.ip_address(a).is_global for a in addresses)
    except Exception:
        return False

def validate_url(value: str):
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only public http/https URLs are allowed")
    if parsed.username or parsed.password or not public_host(parsed.hostname):
        raise ValueError("Private, reserved, or credential-bearing URLs are not allowed")
    return parsed

def fetch_url(url: str, timeout=10, max_bytes=512_000):
    parsed = validate_url(url)
    request = Request(url, headers={"User-Agent": "AI-Security-Auditor/2.0"}, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            final = validate_url(final_url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            raw = response.read(max_bytes + 1)
            return response.status, response.reason, final_url, final, headers, raw[:max_bytes]
    except HTTPError as exc:
        final_url = exc.geturl() or url
        final = validate_url(final_url)
        headers = {k.lower(): v for k, v in exc.headers.items()}
        raw = exc.read(max_bytes + 1)
        return exc.code, exc.reason, final_url, final, headers, raw[:max_bytes]

def finding(severity, title, kind, evidence, why, recommendation):
    return {"severity": severity, "title": title, "type": kind, "evidence": evidence, "why": why, "recommendation": recommendation}

def split_set_cookie(value):
    if not value:
        return []
    return re.split(r",(?=\s*[^;,=\s]+\s*=)", value)

def cookie_findings(value):
    findings = []
    for index, cookie in enumerate(split_set_cookie(value), 1):
        name_match = re.match(r"\s*([^=;\s]+)\s*=", cookie)
        name = name_match.group(1) if name_match else f"Cookie {index}"
        lower = cookie.lower()
        if "secure" not in lower:
            findings.append(finding("medium", f"{name}: Secure attribute missing", "cookie", cookie[:300], "A non-Secure cookie can be exposed if sent over an unencrypted connection.", "Add the Secure attribute when the cookie is intended for HTTPS-only use."))
        if "httponly" not in lower:
            findings.append(finding("medium", f"{name}: HttpOnly attribute missing", "cookie", cookie[:300], "JavaScript can potentially read a cookie that does not use HttpOnly.", "Add HttpOnly unless client-side JavaScript explicitly needs the cookie."))
        if not re.search(r"\bsamesite\s*=", lower):
            findings.append(finding("low", f"{name}: SameSite attribute missing", "cookie", cookie[:300], "SameSite provides an additional cross-site request protection control.", "Set an appropriate SameSite value such as Lax or Strict."))
    return findings

def html_findings(body, base_url):
    findings = []
    text = body.decode("utf-8", "ignore")
    if re.search(r"<form\b[^>]*\baction\s*=\s*[\"']?http://", text, re.I):
        findings.append(finding("medium", "Form submits to HTTP", "mixed-content", "An HTML form action uses http://", "Form data can be transmitted without transport encryption.", "Change form actions to HTTPS URLs or same-origin relative paths."))
    if re.search(r"<(script|img|iframe|link)\b[^>]*(src|href)\s*=\s*[\"']http://", text, re.I):
        findings.append(finding("medium", "HTTP resource referenced by HTTPS page", "mixed-content", "HTML contains an http:// resource reference.", "Mixed content can weaken confidentiality and browser protections.", "Serve referenced resources over HTTPS."))
    if re.search(r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh", text, re.I):
        findings.append(finding("low", "Meta refresh detected", "html", "A meta refresh directive is present.", "Unexpected client-side redirects can complicate navigation and security controls.", "Review whether the meta refresh is necessary."))
    return findings

def scan_target(target: str):
    validate_url(target)
    started = datetime.now(timezone.utc)
    status, reason, final_url, final, headers, body = fetch_url(target)
    findings = []
    passed = []
    failed = []

    for name, (severity, why) in SECURITY_HEADERS.items():
        value = headers.get(name.lower())
        if value:
            passed.append({"check": name, "status": "PASS", "evidence": value[:500], "why": why})
        else:
            findings.append(finding(severity, f"Missing {name}", "security-header", f'Response header "{name}" was not present.', why, SECURITY_RECOMMENDATIONS[name]))

    if final.scheme == "https":
        passed.append({"check": "HTTPS", "status": "PASS", "evidence": final_url, "why": "The final response uses HTTPS."})
    else:
        findings.append(finding("high", "Target is not using HTTPS", "transport", f"Final URL uses {final.scheme}://", "Unencrypted HTTP can expose traffic to interception or modification.", "Serve the site over HTTPS and redirect HTTP to HTTPS."))

    hsts = headers.get("strict-transport-security", "")
    if hsts:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if not match or int(match.group(1)) < 15552000:
            findings.append(finding("low", "HSTS max-age may be short", hsts[:500], "strict-transport-security", "A short HSTS lifetime gives weaker long-term browser enforcement.", "Use an appropriately long max-age after validating the deployment."))

    csp = headers.get("content-security-policy", "")
    if csp and re.search(r"(^|;)\s*(default-src|script-src)\s+[^;]*\*", csp, re.I):
        findings.append(finding("medium", "CSP contains a wildcard source", csp[:500], "csp", "Broad wildcard sources reduce the protection provided by CSP.", "Replace unnecessary wildcard sources with explicit trusted origins."))

    cors = headers.get("access-control-allow-origin")
    if cors == "*":
        findings.append(finding("low", "CORS allows all origins", "cors", "Access-Control-Allow-Origin: *", "Wildcard CORS may expose browser-readable resources more broadly than intended.", "Restrict allowed origins when the resource is not intentionally public."))

    findings.extend(cookie_findings(headers.get("set-cookie", "")))
    findings.extend(html_findings(body, final_url))

    server = headers.get("server")
    powered = headers.get("x-powered-by")
    technologies = []
    if server:
        technologies.append(f"Server: {server}")
        findings.append(finding("low", "Server technology disclosed", "information-disclosure", f"Server: {server}", "Server banners can reveal implementation details.", "Minimize unnecessary server/version disclosure where practical."))
    if powered:
        technologies.append(f"X-Powered-By: {powered}")
        findings.append(finding("low", "X-Powered-By disclosed", "information-disclosure", f"X-Powered-By: {powered}", "Framework/runtime disclosure provides implementation detail.", "Remove X-Powered-By when it is not required."))

    extra = {}
    for path in ("/robots.txt", "/.well-known/security.txt"):
        try:
            s, _, u, _, h, b = fetch_url(urljoin(final_url, path), timeout=6, max_bytes=64_000)
            extra[path] = {"status": s, "url": u, "content_type": h.get("content-type"), "bytes": len(b)}
        except Exception as exc:
            extra[path] = {"status": None, "error": str(exc)}

    failed = [{"check": f["title"], "status": "FAIL", "severity": f["severity"], "evidence": f["evidence"], "why": f["why"], "recommendation": f["recommendation"]} for f in findings]
    counts = {s: sum(f["severity"] == s for f in findings) for s in ("critical", "high", "medium", "low")}
    score = max(0, 100 - counts["critical"]*30 - counts["high"]*15 - counts["medium"]*7 - counts["low"]*3)
    duration = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

    return {
        "target": target, "final_url": final_url, "http_status": status, "status_text": reason,
        "security_score": score, **counts, "findings": findings, "technologies": technologies,
        "security_headers": headers, "passed_checks": passed, "failed_checks": failed,
        "response_summary": {
            "status_text": reason, "content_type": headers.get("content-type"),
            "content_length": headers.get("content-length"), "server": server,
            "powered_by": powered, "set_cookie_present": bool(headers.get("set-cookie")),
            "redirect": final_url if final_url != target else None, "body_bytes_checked": len(body),
            "auxiliary": extra,
        },
        "scan_duration_ms": duration, "scanned_at": now(),
        "mode": "python-detailed-passive-safe-audit"
    }

@app.get("/api/health")
def health():
    return {"agent": "online", "engine": "python-detailed-scanner", "version": "2.0", "time": now()}

@app.get("/api/logs")
def logs():
    return {"logs": _logs[-100:]}

@app.get("/api/last-scan")
def last_scan():
    return _last_scan or {"status": "not_started"}

@app.post("/api/scan")
def scan(request: ScanRequest):
    global _last_scan
    target = str(request.target)
    add_log("Detailed passive security scan started", target)
    try:
        _last_scan = scan_target(target)
    except Exception as exc:
        add_log("Scan failed: " + str(exc), target)
        raise HTTPException(status_code=400, detail=str(exc))
    add_log("Detailed passive security scan completed", target)
    return _last_scan

@app.get("/api/ssl")
def ssl_check(host: str):
    if not public_host(host):
        raise HTTPException(status_code=400, detail="Private or reserved hosts are not allowed")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {"host": host, "tls": ssock.version(), "cipher": ssock.cipher()[0], "subject": cert.get("subject"), "issuer": cert.get("issuer"), "expires": cert.get("notAfter")}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
