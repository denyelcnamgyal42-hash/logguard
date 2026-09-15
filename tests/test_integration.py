from datetime import datetime
from pathlib import Path

from logguard.detection import (
    detect_brute_force,
    detect_multi_account_targeting,
)
from logguard.parser import parse_log_line


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_events(
    filename: str,
    year: int = 2026,
) -> list[dict]:
    log_path = PROJECT_ROOT / "data" / filename

    events = []

    with log_path.open("r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(
                line,
                year=year,
            )

            if event is not None:
                events.append(event)

    return events


def test_sample_log_produces_expected_alert():
    events = load_events("sample_auth.log")

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

    assert len(events) == 5
    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["rule"] == "repeated_failed_logins"
    assert alert["severity"] == "medium"
    assert alert["source_ip"] == "192.168.1.50"
    assert alert["failure_count"] == 3

    assert alert["first_seen"] == datetime(
        2026,
        1,
        10,
        10,
        15,
        32,
    )

    assert alert["last_seen"] == datetime(
        2026,
        1,
        10,
        10,
        15,
        48,
    )


def test_credential_spray_log_detects_multi_account_targeting():
    events = load_events("credential_spray.log")

    alerts = detect_multi_account_targeting(
        events,
        username_threshold=3,
        window_seconds=120,
    )

    assert len(events) == 6
    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["rule"] == "multiple_account_targeting"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "10.10.10.50"
    assert alert["unique_usernames"] == 3

    assert alert["usernames"] == [
        "admin",
        "guest",
        "root",
    ]


def test_credential_spray_log_can_trigger_multiple_rules():
    events = load_events("credential_spray.log")

    brute_force_alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

    account_targeting_alerts = detect_multi_account_targeting(
        events,
        username_threshold=3,
        window_seconds=120,
    )

    assert len(brute_force_alerts) == 1
    assert len(account_targeting_alerts) == 1

    assert (
        brute_force_alerts[0]["source_ip"]
        == account_targeting_alerts[0]["source_ip"]
    )