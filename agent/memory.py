"""Memory layer for storing scan history."""

class AgentMemory:
    def __init__(self):
        self.history = []

    def save(self, result):
        self.history.append(result)

    def get_history(self):
        return self.history
