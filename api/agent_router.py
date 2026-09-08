"""Connect API requests with the AI agent pipeline."""

from datetime import datetime


def run_agent_task(task="security_scan"):
    return {
        "task": task,
        "status": "queued",
        "created": datetime.utcnow().isoformat()
    }


def get_agent_status():
    return {"status": "online"}
