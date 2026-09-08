"""Security report generator."""


def generate_report(findings):
    return {
        "total_findings": len(findings),
        "findings": findings
    }
