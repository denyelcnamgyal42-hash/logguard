from logguard.parser import parse_log_line, parse_syslog_timestamp
import pytest
from datetime import datetime 


def test_failed_login_invalid_user():
    line = (
        "Jan 10 10:15:32 server sshd[1234]: "
        "Failed password for invalid user admin "
        "from 192.168.1.50 port 52341 ssh2"
    )

    result = parse_log_line(line, year=2026)

    assert result == {
    "timestamp": datetime(2026, 1, 10, 10, 15, 32),
    "event": "failed_login",
    "username": "admin",
    "source_ip": "192.168.1.50",
}


def test_successful_login():
    line = (
        "Jan 10 10:16:02 server sshd[1234]: "
        "Accepted password for denye "
        "from 192.168.1.20 port 53000 ssh2"
    )

    result = parse_log_line(line, year = 2026)

    assert result["event"] == "successful_login"
    assert result["username"] == "denye"
    assert result["source_ip"] == "192.168.1.20"


def test_unsupported_line():
    line = "Jan 10 10:17:00 server systemd: Started Session 42."

    result = parse_log_line(line, year = 2026)

    assert result is None


def test_malformed_login_line():
    line = "Failed password for admin"

    result = parse_log_line(line, year = 2026)

    assert result is None

@pytest.mark.parametrize(
    "source_ip",
    [
        "999.168.1.50",
        "192.168.1.9999",
        "192.168.1.50evil",
        "2001:db8::1",
    ],
)
def test_invalid_or_unsupported_ip(source_ip):
    line = (
        "Jan 10 10:15:32 server sshd[1234]: "
        f"Failed password for admin from {source_ip} port 52341 ssh2"
    )

    assert parse_log_line(line, year = 2026) is None


def test_valid_ipv4_is_preserved():
    line = (
        "Jan 10 10:15:32 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 52341 ssh2"
    )

    result = parse_log_line(line, year = 2026)

    assert result["source_ip"] == "192.168.1.50"

def test_parse_syslog_timestamp():
    line = (
        "Jan 10 10:15:32 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 52341 ssh2"
    )

    result = parse_syslog_timestamp(line, year=2026)

    assert result == datetime(2026, 1, 10, 10, 15, 32)


def test_leap_day_timestamp():
    line = "Feb 29 23:59:59 server sshd[1234]: test"

    assert parse_syslog_timestamp(line, year=2024) == datetime(
        2024, 2, 29, 23, 59, 59
    )


@pytest.mark.parametrize(
    "line",
    [
        "Feb 29 10:00:00 server sshd: test",
        "Jan 32 10:00:00 server sshd: test",
        "Jan 10 25:00:00 server sshd: test",
        "Jan 10 10:00:99 server sshd: test",
        "This is not a syslog timestamp",
    ],
)
def test_invalid_syslog_timestamp(line):
    assert parse_syslog_timestamp(line, year=2026) is None