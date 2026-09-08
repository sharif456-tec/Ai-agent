"""Agent activity logger."""

from datetime import datetime


def log_event(message):
    return {
        "time": datetime.utcnow().isoformat(),
        "message": message
    }
