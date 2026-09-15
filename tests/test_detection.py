from datetime import datetime, timedelta

import pytest

from logguard.detection import (
    detect_brute_force,
    detect_multi_account_targeting,
)


def make_event(
    second: int,
    source_ip: str = "192.168.1.50",
    event: str = "failed_login",
    username: str = "admin",
) -> dict:
    return {
        "timestamp": (
            datetime(2026, 1, 10, 10, 0, 0)
            + timedelta(seconds=second)
        ),
        "event": event,
        "username": username,
        "source_ip": source_ip,
    }


def test_detects_three_failures_within_window():
    events = [
        make_event(0),
        make_event(10),
        make_event(20),
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "repeated_failed_logins"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["failure_count"] == 3


def test_does_not_alert_below_threshold():
    events = [
        make_event(0),
        make_event(10),
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

    assert alerts == []


def test_does_not_mix_different_ips():
    events = [
        make_event(0, source_ip="192.168.1.50"),
        make_event(10, source_ip="192.168.1.60"),
        make_event(20, source_ip="192.168.1.50"),
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

    assert alerts == []


def test_successful_logins_do_not_count():
    events = [
        make_event(0),
        make_event(10, event="successful_login"),
        make_event(20),
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

    assert alerts == []


def test_old_failures_expire_from_window():
    events = [
        make_event(0),
        make_event(200),
        make_event(210),
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

    assert alerts == []


def test_unsorted_events_are_handled():
    events = [
        make_event(20),
        make_event(0),
        make_event(10),
    ]

    alerts = detect_brute_force(
        events,
        threshold=3,
        window_seconds=120,
    )

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


def test_threshold_of_one_alerts_immediately():
    alerts = detect_brute_force(
        [make_event(0)],
        threshold=1,
        window_seconds=120,
    )

    assert len(alerts) == 1


@pytest.mark.parametrize(
    "threshold",
    [0, -1],
)
def test_invalid_threshold_raises_error(threshold):
    with pytest.raises(
        ValueError,
        match="threshold must be at least 1",
    ):
        detect_brute_force(
            [],
            threshold=threshold,
            window_seconds=120,
        )


@pytest.mark.parametrize(
    "window_seconds",
    [0, -1],
)
def test_invalid_window_raises_error(window_seconds):
    with pytest.raises(
        ValueError,
        match="window_seconds must be positive",
    ):
        detect_brute_force(
            [],
            threshold=3,
            window_seconds=window_seconds,
        )


def test_detects_multiple_account_targeting():
    events = [
        make_event(0, username="admin"),
        make_event(10, username="root"),
        make_event(20, username="guest"),
    ]

    alerts = detect_multi_account_targeting(
        events,
        username_threshold=3,
        window_seconds=120,
    )

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["rule"] == "multiple_account_targeting"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "192.168.1.50"
    assert alert["unique_usernames"] == 3
    assert alert["usernames"] == [
        "admin",
        "guest",
        "root",
    ]


def test_repeated_same_username_does_not_trigger_multi_account_rule():
    events = [
        make_event(0, username="admin"),
        make_event(10, username="admin"),
        make_event(20, username="admin"),
    ]

    alerts = detect_multi_account_targeting(
        events,
        username_threshold=3,
        window_seconds=120,
    )

    assert alerts == []


def test_multi_account_rule_does_not_mix_ips():
    events = [
        make_event(
            0,
            source_ip="192.168.1.50",
            username="admin",
        ),
        make_event(
            10,
            source_ip="192.168.1.60",
            username="root",
        ),
        make_event(
            20,
            source_ip="192.168.1.50",
            username="guest",
        ),
    ]

    alerts = detect_multi_account_targeting(
        events,
        username_threshold=3,
        window_seconds=120,
    )

    assert alerts == []


def test_successful_login_does_not_count_for_multi_account_rule():
    events = [
        make_event(0, username="admin"),
        make_event(
            10,
            username="root",
            event="successful_login",
        ),
        make_event(20, username="guest"),
    ]

    alerts = detect_multi_account_targeting(
        events,
        username_threshold=3,
        window_seconds=120,
    )

    assert alerts == []


def test_multi_account_old_events_expire():
    events = [
        make_event(0, username="admin"),
        make_event(200, username="root"),
        make_event(210, username="guest"),
    ]

    alerts = detect_multi_account_targeting(
        events,
        username_threshold=3,
        window_seconds=120,
    )

    assert alerts == []


def test_multi_account_unsorted_events_are_handled():
    events = [
        make_event(20, username="guest"),
        make_event(0, username="admin"),
        make_event(10, username="root"),
    ]

    alerts = detect_multi_account_targeting(
        events,
        username_threshold=3,
        window_seconds=120,
    )

    assert len(alerts) == 1


def test_multi_account_invalid_threshold():
    with pytest.raises(
        ValueError,
        match="username_threshold must be at least 2",
    ):
        detect_multi_account_targeting(
            [],
            username_threshold=1,
            window_seconds=120,
        )