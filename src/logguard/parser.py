import re
from ipaddress import IPv4Address
from datetime import datetime

def parse_syslog_timestamp(line: str, year: int) -> datetime | None:
    """Parse a traditional syslog timestamp using an explicit year."""

    match = re.match(
        r"^(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})(?=\s)",
        line,
    )

    if match is None:
        return None

    timestamp_text = (
        f"{year} {match.group('month')} "
        f"{match.group('day')} {match.group('time')}"
    )

    try:
        return datetime.strptime(
            timestamp_text,
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def parse_log_line(line: str, year: int) -> dict | None:
    """Parse an SSH authentication log line."""

    timestamp = parse_syslog_timestamp(line, year)
    if not timestamp:
        return None

    if "Failed password" in line:
        event = "failed_login"
    elif "Accepted password" in line:
        event = "successful_login"
    else:
        return None

    username_match = re.search(
        r"for (?:invalid user )?(\S+) from",
        line,
    )

    ip_match = re.search(
        r"\bfrom (\S+)(?:\s|$)",
        line,
    )

    if not username_match or not ip_match:
        return None

    try:
        source_ip = IPv4Address(ip_match.group(1))
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "event": event,
        "username": username_match.group(1),
        "source_ip": str(source_ip),
    }