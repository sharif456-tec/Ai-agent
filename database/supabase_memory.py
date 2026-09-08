"""Supabase memory layer foundation for AI Security Agent."""

from datetime import datetime


class SupabaseMemory:
    def __init__(self):
        self.connected = False

    def connect(self):
        self.connected = True
        return {"status": "connected"}

    def save_scan(self, result):
        return {
            "saved": True,
            "time": datetime.utcnow().isoformat(),
            "result": result,
        }

    def get_history(self):
        return []
