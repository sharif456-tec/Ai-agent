"""Risk scoring module for authorized security audits."""


def calculate_risk(findings_count):
    if findings_count == 0:
        return "LOW"
    if findings_count < 5:
        return "MEDIUM"
    return "HIGH"
