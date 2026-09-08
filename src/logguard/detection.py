from collections import defaultdict, deque
from datetime import timedelta


def detect_brute_force(
    events: list[dict],
    threshold: int = 3,
    window_seconds: int = 120,
) -> list[dict]:
    """Detect repeated failed logins from the same IP."""

    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    events = sorted(events, key=lambda event: event["timestamp"])

    failures = defaultdict(deque)
    alerts = []

    for event in events:
        if event["event"] != "failed_login":
            continue

        source_ip = event["source_ip"]
        timestamp = event["timestamp"]
        window = failures[source_ip]

        window.append(timestamp)

        cutoff = timestamp - timedelta(seconds=window_seconds)

        while window and window[0] < cutoff:
            window.popleft()

        if len(window) == threshold:
            alerts.append(
                {
                    "rule": "repeated_failed_logins",
                    "source_ip": source_ip,
                    "failure_count": len(window),
                    "first_seen": window[0],
                    "last_seen": window[-1],
                }
            )

    return alerts