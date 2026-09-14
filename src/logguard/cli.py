import argparse
from pathlib import Path

from logguard.detection import detect_brute_force
from logguard.parser import parse_log_line


def analyze_log(
    log_path: Path,
    year: int,
    threshold: int,
    window_seconds: int,
) -> None:
    events = []

    with log_path.open("r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(line, year=year)

            if event is not None:
                events.append(event)

    alerts = detect_brute_force(
        events,
        threshold=threshold,
        window_seconds=window_seconds,
    )

    print(f"File: {log_path}")
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


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="logguard",
        description="Analyze authentication logs for suspicious activity.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an authentication log file.",
    )

    analyze_parser.add_argument(
        "logfile",
        type=Path,
        help="Path to the authentication log file.",
    )

    analyze_parser.add_argument(
        "--year",
        type=int,
        required=True,
        help="Year associated with traditional syslog timestamps.",
    )

    analyze_parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Failed login attempts required to trigger an alert.",
    )

    analyze_parser.add_argument(
        "--window",
        type=int,
        default=120,
        help="Detection window in seconds.",
    )

    args = parser.parse_args()

    if args.command == "analyze":
        if not args.logfile.exists():
            parser.error(f"log file does not exist: {args.logfile}")

        analyze_log(
            log_path=args.logfile,
            year=args.year,
            threshold=args.threshold,
            window_seconds=args.window,
        )


if __name__ == "__main__":
    main()