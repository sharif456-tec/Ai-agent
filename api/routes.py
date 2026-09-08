"""Final API route definitions for AI Security Command Center."""

from datetime import datetime

_logs = []


def health():
    return {
        "status": "online",
        "service": "AI Security Agent",
        "time": datetime.utcnow().isoformat()
    }


def start_scan(target=None):
    event = {
        "event": "scan_started",
        "target": target or "manual",
        "time": datetime.utcnow().isoformat()
    }
    _logs.append(event)
    return event


def get_logs():
    return {
        "logs": _logs[-50:]
    }


def agent_status():
    return {
        "agent": "ready",
        "queue": "idle"
    }
