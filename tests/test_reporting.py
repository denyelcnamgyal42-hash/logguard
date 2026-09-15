import json
from datetime import datetime
from pathlib import Path

from logguard.reporting import build_report, write_json_report


def test_build_report_summary():
    events = [
        {
            "timestamp": datetime(2026, 1, 10, 10, 0, 0),
            "event": "failed_login",
            "username": "admin",
            "source_ip": "192.168.1.50",
        },
        {
            "timestamp": datetime(2026, 1, 10, 10, 1, 0),
            "event": "successful_login",
            "username": "denye",
            "source_ip": "192.168.1.20",
        },
    ]

    alerts = []

    report = build_report(
        Path("sample.log"),
        events,
        alerts,
    )

    summary = report["summary"]

    assert summary["total_events"] == 2
    assert summary["failed_logins"] == 1
    assert summary["successful_logins"] == 1
    assert summary["unique_source_ips"] == 2
    assert summary["security_alerts"] == 0


def test_write_json_report(tmp_path):
    report = {
        "summary": {
            "total_events": 5,
        }
    }

    output_path = tmp_path / "report.json"

    write_json_report(
        report,
        output_path,
    )

    assert output_path.exists()

    saved_report = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert saved_report["summary"]["total_events"] == 5