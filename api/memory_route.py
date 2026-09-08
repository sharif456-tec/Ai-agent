from datetime import datetime

# Supabase memory API route foundation

async def save_agent_memory(memory_store, event_type, payload):
    return await memory_store.insert({
        "event_type": event_type,
        "payload": payload,
        "created_at": datetime.utcnow().isoformat()
    })

async def get_agent_memory(memory_store, limit=50):
    return await memory_store.select(limit=limit)
