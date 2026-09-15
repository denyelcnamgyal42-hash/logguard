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

    sorted_events = sorted(
        events,
        key=lambda event: event["timestamp"],
    )

    failures = defaultdict(deque)
    last_failure = {}
    alerted_in_episode = defaultdict(bool)

    alerts = []

    window_duration = timedelta(seconds=window_seconds)

    for event in sorted_events:
        if event["event"] != "failed_login":
            continue

        source_ip = event["source_ip"]
        timestamp = event["timestamp"]

        previous_failure = last_failure.get(source_ip)

        if (
            previous_failure is not None
            and timestamp - previous_failure > window_duration
        ):
            failures[source_ip].clear()
            alerted_in_episode[source_ip] = False

        last_failure[source_ip] = timestamp

        window = failures[source_ip]
        window.append(timestamp)

        cutoff = timestamp - window_duration

        while window and window[0] < cutoff:
            window.popleft()

        if (
            len(window) >= threshold
            and not alerted_in_episode[source_ip]
        ):
            alerts.append(
                {
                    "rule": "repeated_failed_logins",
                    "severity": "medium",
                    "source_ip": source_ip,
                    "failure_count": len(window),
                    "first_seen": window[0],
                    "last_seen": window[-1],
                }
            )

            alerted_in_episode[source_ip] = True

    return alerts


def detect_multi_account_targeting(
    events: list[dict],
    username_threshold: int = 3,
    window_seconds: int = 120,
) -> list[dict]:
    """Detect one IP failing authentication against many usernames."""

    if username_threshold < 2:
        raise ValueError("username_threshold must be at least 2")

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    sorted_events = sorted(
        events,
        key=lambda event: event["timestamp"],
    )

    failures = defaultdict(deque)
    alerted_in_episode = defaultdict(bool)
    last_failure = {}

    alerts = []

    window_duration = timedelta(seconds=window_seconds)

    for event in sorted_events:
        if event["event"] != "failed_login":
            continue

        source_ip = event["source_ip"]
        timestamp = event["timestamp"]
        username = event["username"]

        previous_failure = last_failure.get(source_ip)

        if (
            previous_failure is not None
            and timestamp - previous_failure > window_duration
        ):
            failures[source_ip].clear()
            alerted_in_episode[source_ip] = False

        last_failure[source_ip] = timestamp

        window = failures[source_ip]

        window.append(
            {
                "timestamp": timestamp,
                "username": username,
            }
        )

        cutoff = timestamp - window_duration

        while (
            window
            and window[0]["timestamp"] < cutoff
        ):
            window.popleft()

        usernames = {
            item["username"]
            for item in window
        }

        if (
            len(usernames) >= username_threshold
            and not alerted_in_episode[source_ip]
        ):
            alerts.append(
                {
                    "rule": "multiple_account_targeting",
                    "severity": "high",
                    "source_ip": source_ip,
                    "unique_usernames": len(usernames),
                    "usernames": sorted(usernames),
                    "first_seen": window[0]["timestamp"],
                    "last_seen": window[-1]["timestamp"],
                }
            )

            alerted_in_episode[source_ip] = True

    return alerts