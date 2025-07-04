import argparse
from pathlib import Path
import pytest
from datetime import UTC, datetime as dt, timedelta, timezone
import pytz
import re

from cve2stix.config import Config
import run_cve2stix as cve2stix

# -----------------------------------------
# valid_date
# -----------------------------------------


def test_valid_date_parses_correct_format():
    s = "2025-07-03T15:00:00"
    parsed = cve2stix.valid_date(s)
    assert parsed == pytz.utc.localize(dt(2025, 7, 3, 15, 0, 0))
    assert parsed.tzinfo.zone == "UTC"


def test_valid_date_raises_on_invalid():
    with pytest.raises(argparse.ArgumentTypeError):
        # because argparse.ArgumentTypeError exits with code 2
        cve2stix.valid_date("2025/07/03")


# -----------------------------------------
# parse_time_range
# -----------------------------------------


@pytest.mark.parametrize(
    "arg,expected",
    [
        ("1d", ("1", "d")),
        ("6m", ("6", "m")),
        ("2y", ("2", "y")),
    ],
)
def test_parse_time_range_valid(arg, expected):
    s = cve2stix.parse_time_range(arg)
    assert s == arg  # it just returns same string if valid


def test_parse_time_range_errors_on_bad_unit():
    with pytest.raises(argparse.ArgumentTypeError):
        cve2stix.parse_time_range("3w")


def test_parse_time_range_errors_on_zero():
    with pytest.raises(argparse.ArgumentTypeError):
        cve2stix.parse_time_range("0d")


def test_parse_time_range_errors_on_bad_format():
    with pytest.raises(argparse.ArgumentTypeError):
        cve2stix.parse_time_range("d3")


# -----------------------------------------
# get_time_ranges
# -----------------------------------------
def date_string(date: dt):
    return date.strftime("%Y-%m-%dT%H:%M:%S")


@pytest.mark.parametrize(
    ["earliest", "latest", "timerange_arg", "expected_ranges"],
    [
        # 1 day slices
        (
            dt(2025, 7, 1, 11, 1, 25, tzinfo=timezone.utc),
            dt(2025, 7, 3, 12, 14, tzinfo=timezone.utc),
            "1d",
            [
                ("2025-07-01T11:01:25", "2025-07-01T23:59:59"),
                ("2025-07-02T00:00:00", "2025-07-02T23:59:59"),
                ("2025-07-03T00:00:00", "2025-07-03T12:14:00"),
            ],
        ),
        # 1 month slices
        (
            dt(2025, 6, 15, 8, 0, 0, tzinfo=timezone.utc),
            dt(2025, 8, 10, 9, 0, 0, tzinfo=timezone.utc),
            "1m",
            [
                ("2025-06-15T08:00:00", "2025-06-30T23:59:59"),
                ("2025-07-01T00:00:00", "2025-07-31T23:59:59"),
                ("2025-08-01T00:00:00", "2025-08-10T09:00:00"),
            ],
        ),
        # 1 year slices
        (
            dt(2023, 11, 15, 8, 0, 0, tzinfo=timezone.utc),
            dt(2025, 3, 10, 9, 0, 0, tzinfo=timezone.utc),
            "1y",
            [
                ("2023-11-15T08:00:00", "2023-12-31T23:59:59"),
                ("2024-01-01T00:00:00", "2024-12-31T23:59:59"),
                ("2025-01-01T00:00:00", "2025-03-10T09:00:00"),
            ],
        ),
    ],
)
def test_get_time_ranges(earliest, latest, timerange_arg, expected_ranges):
    ranges = cve2stix.get_time_ranges(timerange_arg, earliest, latest)
    dates = [(date_string(lo), date_string(hi)) for _, lo, hi in ranges]
    assert dates == expected_ranges
    # Should produce at least two ranges for these examples
    assert len(ranges) >= 2
    for unit, lo, hi in ranges:
        assert lo < hi


# -----------------------------------------
# parse_args with mocked sys.argv
# -----------------------------------------

import sys
from unittest.mock import MagicMock, call, patch


def test_parse_args_mod(monkeypatch):
    # patch sys.argv
    testargs = [
        "prog",
        "mod",
        "--earliest",
        "2025-07-01T00:00:00",
        "--latest",
        "2025-07-03T23:59:59",
    ]
    monkeypatch.setattr(sys, "argv", testargs)
    args = cve2stix.parse_args()
    assert args.mode == "mod"
    assert args.earliest < args.latest
    assert args.file_time_range == "1m"


def test_parse_args_pub_defaults(monkeypatch):
    testargs = ["prog", "pub"]
    monkeypatch.setattr(sys, "argv", testargs)
    args = cve2stix.parse_args()
    assert args.mode == "pub"
    assert args.earliest <= args.latest
    assert isinstance(args.earliest, dt)


def test_parse_args_raises_on_invalid_range(monkeypatch):
    testargs = [
        "prog",
        "mod",
        "--earliest",
        "2025-07-03T00:00:00",
        "--latest",
        "2025-07-01T23:59:59",
    ]
    monkeypatch.setattr(sys, "argv", testargs)
    with pytest.raises(argparse.ArgumentError):
        cve2stix.parse_args()


def test_help_action(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "--help"])
    with pytest.raises(SystemExit):
        cve2stix.parse_args()


# patch to avoid actual file creation and celery starting
@pytest.fixture
def patched_env(monkeypatch):
    # Mock celery start
    mock_celery_process = MagicMock()
    monkeypatch.setattr(
        "run_cve2stix.start_celery", lambda *a, **k: mock_celery_process
    )

    # Mock check_online_status to just pass
    monkeypatch.setattr("run_cve2stix.check_online_status", lambda: None)

    # Mock download_bundle to record calls
    mock_download_bundle = MagicMock()
    monkeypatch.setattr("run_cve2stix.download_bundle", mock_download_bundle)

    return mock_celery_process, mock_download_bundle


def test_run_mod_mode(monkeypatch, patched_env):
    celery_proc, mock_download_bundle = patched_env

    # Simulate CLI input
    testargs = [
        "prog",
        "mod",
        "--earliest",
        "2025-07-01T00:00:00",
        "--latest",
        "2025-07-03T23:59:59",
        "--file_time_range",
        "1d",
    ]
    monkeypatch.setattr(sys, "argv", testargs)

    # run it
    cve2stix.run()

    # verify celery was started and killed
    celery_proc.kill.assert_called_once()

    # verify download_bundle was called multiple times (once per time range split)
    assert mock_download_bundle.call_count == 3
    calls = mock_download_bundle.call_args_list
    assert calls == [
        call(
            dt(2025, 7, 1, 0, 0, tzinfo=UTC),
            dt(2025, 7, 1, 23, 59, 59, tzinfo=UTC),
            filename="2025-07/cve-bundle-2025_07_01-00_00_00-2025_07_01-23_59_59.json",
            config=Config(
                type="cve",
                filter_mode="lastMod",
                start_date=dt(2025, 7, 1, 0, 0, tzinfo=UTC),
                end_date=dt(2025, 7, 1, 23, 59, 59, tzinfo=UTC),
                stix2_objects_folder=str(Path("output/objects/cve_objects-2025_07_01-00_00_00-2025_07_01-23_59_59").absolute()),
                stix2_bundles_folder=str(Path("output/bundles").absolute()),
                store_in_filestore=True,
                disable_parsing=False,
                cve_id="",
                cve_cvssV3_severity="",
                nvd_cve_api_endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0/",
                cpematch_api_endpoint="https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId=",
                results_per_page=500,
                nvd_api_key=None,
                file_system=str(Path("output/objects/cve_objects-2025_07_01-00_00_00-2025_07_01-23_59_59").absolute()),
            ),
        ),
        call(
            dt(2025, 7, 2, 0, 0, tzinfo=UTC),
            dt(2025, 7, 2, 23, 59, 59, tzinfo=UTC),
            filename="2025-07/cve-bundle-2025_07_02-00_00_00-2025_07_02-23_59_59.json",
            config=Config(
                type="cve",
                filter_mode="lastMod",
                start_date=dt(2025, 7, 2, 0, 0, tzinfo=UTC),
                end_date=dt(2025, 7, 2, 23, 59, 59, tzinfo=UTC),
                stix2_objects_folder=str(Path("output/objects/cve_objects-2025_07_02-00_00_00-2025_07_02-23_59_59").absolute()),
                stix2_bundles_folder=str(Path("output/bundles").absolute()),
                store_in_filestore=True,
                disable_parsing=False,
                cve_id="",
                cve_cvssV3_severity="",
                nvd_cve_api_endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0/",
                cpematch_api_endpoint="https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId=",
                results_per_page=500,
                nvd_api_key=None,
                file_system=str(Path("output/objects/cve_objects-2025_07_02-00_00_00-2025_07_02-23_59_59").absolute()),
            ),
        ),
        call(
            dt(2025, 7, 3, 0, 0, tzinfo=UTC),
            dt(2025, 7, 3, 23, 59, 59, tzinfo=UTC),
            filename="2025-07/cve-bundle-2025_07_03-00_00_00-2025_07_03-23_59_59.json",
            config=Config(
                type="cve",
                filter_mode="lastMod",
                start_date=dt(2025, 7, 3, 0, 0, tzinfo=UTC),
                end_date=dt(2025, 7, 3, 23, 59, 59, tzinfo=UTC),
                stix2_objects_folder=str(Path("output/objects/cve_objects-2025_07_03-00_00_00-2025_07_03-23_59_59").absolute()),
                stix2_bundles_folder=str(Path("output/bundles").absolute()),
                store_in_filestore=True,
                disable_parsing=False,
                cve_id="",
                cve_cvssV3_severity="",
                nvd_cve_api_endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0/",
                cpematch_api_endpoint="https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId=",
                results_per_page=500,
                nvd_api_key=None,
                file_system=str(Path("output/objects/cve_objects-2025_07_03-00_00_00-2025_07_03-23_59_59").absolute()),
            ),
        ),
    ]

def test_run_pub_mode(monkeypatch, patched_env):
    celery_proc, mock_download_bundle = patched_env

    # Simulate CLI input
    testargs = ["prog", "pub", "--file_time_range", "1m"]
    monkeypatch.setattr(sys, "argv", testargs)

    cve2stix.run()

    celery_proc.kill.assert_called_once()
    assert mock_download_bundle.called
    assert mock_download_bundle.call_args_list[0].kwargs['config'].filter_mode == "pub"
