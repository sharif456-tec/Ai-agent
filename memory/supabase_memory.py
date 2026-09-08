from backend.supabase_client import get_supabase
from datetime import datetime, timezone


def save_agent_memory(event_type, payload):
    db = get_supabase()
    if not db:
        return {"status": "offline", "message": "Supabase not configured"}

    data = {
        "event_type": event_type,
        "payload": payload,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    return db.table("agent_memory").insert(data).execute()


def get_agent_memory(limit=50):
    db = get_supabase()
    if not db:
        return []

    result = db.table("agent_memory").select("*").order("created_at", desc=True).limit(limit).execute()
    return result.data
