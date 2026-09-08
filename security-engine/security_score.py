"""AI Security Score Engine"""


def calculate_score(findings):
    score = 100
    weights = {"critical": 25, "high": 15, "medium": 7, "low": 2}
    for item in findings:
        score -= weights.get(item.get("severity", "low"), 0)
    return max(0, score)
