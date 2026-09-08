from pathlib import Path

from logguard.parser import parse_log_line
from logguard.detection import detect_brute_force


def main() -> None:
    log_path = Path("data/sample_auth.log")
    events = []

    with log_path.open("r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(line, year=2026)

            if event is not None:
                events.append(event)

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

    print(f"Parsed events: {len(events)}")
    print(f"Security alerts: {len(alerts)}")

    for alert in alerts:
        print()
        print("=== SECURITY ALERT ===")
        print(f"Rule: {alert['rule']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failed attempts: {alert['failure_count']}")
        print(f"First seen: {alert['first_seen']}")
        print(f"Last seen: {alert['last_seen']}")


if __name__ == "__main__":
    main()