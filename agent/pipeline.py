"""AI Agent execution pipeline."""

from agent.planner import create_plan


def run_agent(target):
    plan = create_plan(target)
    return {
        "target": target,
        "plan": plan,
        "status": "ready"
    }
