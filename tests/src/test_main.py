import pytest
from unittest.mock import patch, MagicMock
from datetime import UTC, datetime, timedelta, timezone

from cve2stix import main
from cve2stix.config import Config, FilterMode


@pytest.fixture(autouse=True)
def celery_always_eager(celery_eager):
    """
    Force Celery to run tasks synchronously in tests
    """
    yield


def test_main_runs_chord_flow(celery_always_eager, config):
    with (
        patch("cve2stix.main.clean_filesystem") as mock_clean,
        patch("cve2stix.main.cve_syncing_task.run") as mock_syncing,
        patch("cve2stix.main.preparing_results.run") as mock_prepare,
    ):
        # Arrange
        mock_result = MagicMock()
        mock_prepare.return_value = "prepared_result"
        start_date, end_date = datetime(2025, 7, 1, 0, 0, tzinfo=UTC), datetime(
            2025, 7, 12, 0, 0, tzinfo=UTC
        )
        # Act
        result = main.main(start_date, end_date, config=config)

        # Assert
        mock_clean.assert_called_once_with(config.file_system)
        assert mock_syncing.call_args[0][:2] == (
            start_date,
            end_date,
        )
        assert mock_prepare.called
        assert result == "prepared_result"


def test_parse_date_variants():
    # string
    s = main._parse_date("2025-07-01T12:00:00")
    assert s.year == 2025 and s.month == 7 and s.hour == 12

    # datetime
    d = datetime(2025, 7, 1, 12, 5, 1, tzinfo=timezone.utc)
    s2 = main._parse_date(d)
    assert s2 == d

    # date
    from datetime import date

    d3 = main._parse_date(date(2025, 7, 1))
    assert d3.year == 2025 and d3.month == 7


def test_map_identity_adds_identity_to_list_and_fs(config):
    obj_list = []
    with patch("stix2.FileSystemStore.add") as mock_fs_add:
        out = main.map_identity(config, obj_list)
        assert any(o for o in out if getattr(o, "type", None) == "identity")
        mock_fs_add.assert_called()


def test_map_marking_definition_adds_marking_to_list_and_fs(config):
    obj_list = []
    with patch("stix2.FileSystemStore.add") as mock_fs_add:
        out = main.map_marking_definition(config, obj_list)
        assert any(o for o in out if getattr(o, "type", None) == "marking-definition")
        mock_fs_add.assert_called()


def test_map_extensions_adds_extensions_and_fs(config):
    with patch("stix2.FileSystemStore.add") as mock_fs_add:
        obj_list = [1, 2, 3]
        out = main.map_extensions(config, obj_list)
        assert {d["id"] for d in out[3:]} == {
            "extension-definition--2c5c13af-ee92-5246-9ba7-0b958f8cd34a",
            "extension-definition--82cad0bb-0906-5885-95cc-cafe5ee0a500",
            "extension-definition--ec658473-1319-53b4-879f-488e47805554",
            "extension-definition--ad995824-2901-5f6e-890b-561130a239d4",
        }
        mock_fs_add.assert_called_with(out[3:])  # last 3 are extensions


def test_fetch_data(config):
    with patch("cve2stix.main.fetch_url") as mock_fetch_url:
        config.filter_mode = FilterMode.MOD_DATE
        main.fetch_data(
            datetime(2025, 7, 1, tzinfo=timezone.utc),
            datetime(2025, 8, 1, tzinfo=timezone.utc),
            config,
        )
        mock_fetch_url.assert_called_once_with(
            "https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2025-07-01T00%3A00%3A00Z&lastModEndDate=2025-08-01T00%3A00%3A00Z",
            config,
            main.parse_cve_api_response,
        )

        mock_fetch_url.reset_mock()
        config.filter_mode = FilterMode.PUB_DATE
        main.fetch_data(
            datetime(2025, 7, 1, tzinfo=timezone.utc),
            datetime(2025, 8, 1, tzinfo=timezone.utc),
            config,
        )
        mock_fetch_url.assert_called_once_with(
            "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=2025-07-01T00%3A00%3A00Z&pubEndDate=2025-08-01T00%3A00%3A00Z",
            config,
            main.parse_cve_api_response,
        )
