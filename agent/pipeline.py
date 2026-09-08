"""AI Agent execution pipeline."""

from agent.planner import create_plan
from agent.network_scanner import universal_network_scanner
from agent.brain import SecurityAgentBrain


def run_agent(target, scan_method="nmap", ports="80,443"):
    plan = create_plan(target)

    scan_result = universal_network_scanner(
        target=target,
        method=scan_method,
        ports=ports
    )

    brain = SecurityAgentBrain()
    analysis = brain.analyze(scan_result)

    return {
        "target": target,
        "plan": plan,
        "network_scan": scan_result,
        "ai_analysis": analysis,
        "status": "completed"
    }
