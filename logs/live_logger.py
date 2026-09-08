"""Live log stream foundation for command center."""

_logs = []


def add_log(message):
    _logs.append(message)


def get_logs():
    return _logs
