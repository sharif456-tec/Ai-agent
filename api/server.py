"""API entry point for AI Security Command Center."""

from datetime import datetime


def health_check():
    return {
        "agent": "online",
        "time": datetime.utcnow().isoformat()
    }


def start_scan():
    return {
        "status": "queued",
        "message": "Security scan task queued",
        "time": datetime.utcnow().isoformat()
    }
