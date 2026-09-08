from datetime import datetime
from pathlib import Path

from logguard.detection import detect_brute_force
from logguard.parser import parse_log_line


def test_sample_log_produces_expected_alert():
    # Locate the project root from this test file.
    project_root = Path(__file__).resolve().parents[1]
    log_path = project_root / "data" / "sample_auth.log"

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

    assert len(events) == 5
    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["rule"] == "repeated_failed_logins"
    assert alert["source_ip"] == "192.168.1.50"
    assert alert["failure_count"] == 3
    assert alert["first_seen"] == datetime(2026, 1, 10, 10, 15, 32)
    assert alert["last_seen"] == datetime(2026, 1, 10, 10, 15, 48)