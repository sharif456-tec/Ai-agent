"""Generate security audit summaries."""


def create_report(target, findings):
    score = max(0, 100 - (len(findings) * 5))
    return {
        "target": target,
        "security_score": score,
        "findings": findings,
        "recommendation": "Review missing security controls and apply fixes."
    }
