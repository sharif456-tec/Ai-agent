import json
from datetime import datetime

MEMORY_FILE = "memory/store.json"


def save_memory(event, data):
    record = {
        "time": datetime.utcnow().isoformat(),
        "event": event,
        "data": data
    }

    try:
        with open(MEMORY_FILE, "r") as f:
            memory = json.load(f)
    except Exception:
        memory = []

    memory.append(record)

    with open(MEMORY_FILE, "w") as f:
        json.dump(memory, f, indent=2)


def get_memory(limit=50):
    try:
        with open(MEMORY_FILE, "r") as f:
            memory = json.load(f)
        return memory[-limit:]
    except Exception:
        return []
