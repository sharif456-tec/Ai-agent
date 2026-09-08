"""Security header checker for authorized audits."""

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def analyze_headers(headers):
    result = {}
    for header in SECURITY_HEADERS:
        result[header] = "present" if header in headers else "missing"
    return result
