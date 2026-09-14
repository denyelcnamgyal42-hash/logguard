import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_logguard(*args: str):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "logguard.cli",
            *args,
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )


def test_cli_help():
    result = run_logguard("--help")

    assert result.returncode == 0
    assert "Analyze authentication logs" in result.stdout
    assert "analyze" in result.stdout


def test_cli_analyze_sample_log():
    result = run_logguard(
        "analyze",
        "data/sample_auth.log",
        "--year",
        "2026",
    )

    assert result.returncode == 0
    assert "Parsed events: 5" in result.stdout
    assert "Security alerts: 1" in result.stdout
    assert "192.168.1.50" in result.stdout


def test_cli_threshold_can_be_changed():
    result = run_logguard(
        "analyze",
        "data/sample_auth.log",
        "--year",
        "2026",
        "--threshold",
        "4",
    )

    assert result.returncode == 0
    assert "Security alerts: 0" in result.stdout


def test_cli_rejects_missing_file():
    result = run_logguard(
        "analyze",
        "data/does-not-exist.log",
        "--year",
        "2026",
    )

    assert result.returncode != 0
    assert "log file does not exist" in result.stderr