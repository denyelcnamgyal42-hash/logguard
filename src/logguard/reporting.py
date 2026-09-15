import json
from datetime import datetime
from pathlib import Path


def build_report(
    log_path: Path,
    events: list[dict],
    alerts: list[dict],
) -> dict:
    """Build a structured security analysis report."""

    failed_logins = sum(
        1 for event in events
        if event["event"] == "failed_login"
    )

    successful_logins = sum(
        1 for event in events
        if event["event"] == "successful_login"
    )

    unique_ips = {
        event["source_ip"]
        for event in events
    }

    return {
        "source_file": str(log_path),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "total_events": len(events),
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "unique_source_ips": len(unique_ips),
            "security_alerts": len(alerts),
        },
        "alerts": alerts,
    }


def write_json_report(
    report: dict,
    output_path: Path,
) -> None:
    """Write a report to a JSON file."""

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=2,
            default=str,
        )