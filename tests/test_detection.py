from datetime import datetime, timedelta

from logguard.detection import detect_brute_force


def make_event(second, source_ip="192.168.1.50", event="failed_login"):
    return {
        "timestamp": datetime(2026, 1, 10, 10, 0, 0)
        + timedelta(seconds=second),
        "event": event,
        "username": "admin",
        "source_ip": source_ip,
    }


def test_detects_three_failures_within_window():
    events = [
        make_event(0),
        make_event(10),
        make_event(20),
    ]

    alerts = detect_brute_force(events, threshold=3, window_seconds=120)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["failure_count"] == 3


def test_does_not_alert_below_threshold():
    events = [make_event(0), make_event(10)]

    alerts = detect_brute_force(events, threshold=3, window_seconds=120)

    assert alerts == []


def test_does_not_mix_different_ips():
    events = [
        make_event(0, "192.168.1.50"),
        make_event(10, "192.168.1.60"),
        make_event(20, "192.168.1.50"),
    ]

    alerts = detect_brute_force(events, threshold=3, window_seconds=120)

    assert alerts == []


def test_successful_logins_do_not_count():
    events = [
        make_event(0),
        make_event(10, event="successful_login"),
        make_event(20),
    ]

    alerts = detect_brute_force(events, threshold=3, window_seconds=120)

    assert alerts == []


def test_old_failures_expire_from_window():
    events = [
        make_event(0),
        make_event(200),
        make_event(210),
    ]

    alerts = detect_brute_force(events, threshold=3, window_seconds=120)

    assert alerts == []


def test_unsorted_events_are_handled():
    events = [
        make_event(20),
        make_event(0),
        make_event(10),
    ]

    alerts = detect_brute_force(events, threshold=3, window_seconds=120)

    assert len(alerts) == 1

def test_separate_bursts_produce_separate_alerts():
    events = [
        make_event(0),
        make_event(10),
        make_event(20),
        make_event(4 * 60 * 60),
        make_event(4 * 60 * 60 + 10),
        make_event(4 * 60 * 60 + 20),
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

    assert len(alerts) == 2
    assert alerts[0]["failure_count"] == 3
    assert alerts[1]["failure_count"] == 3

def test_continuous_burst_produces_only_one_alert():
    events = [
        make_event(0),
        make_event(10),
        make_event(20),
        make_event(30),
        make_event(40),
        make_event(50),
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

    assert len(alerts) == 1