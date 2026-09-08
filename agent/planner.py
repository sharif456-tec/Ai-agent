"""Task planner for Ethical AI Security Agent."""


def create_plan(target):
    return [
        {"task": "asset_check", "target": target},
        {"task": "security_headers_check", "target": target},
        {"task": "risk_analysis", "target": target},
        {"task": "generate_report", "target": target},
    ]
