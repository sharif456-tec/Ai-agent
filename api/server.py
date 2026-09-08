"""API entry point for AI Security Command Center."""

from datetime import datetime


def health_check():
    return {
        "agent": "online",
        "time": datetime.utcnow().isoformat()
    }
