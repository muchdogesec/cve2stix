import pytest
from unittest import mock
from unittest.mock import MagicMock, patch
import cve2stix.celery as celery_mod
import sys


def test_check_online_status_returns_ping(monkeypatch):
    mock_ping = {'worker1': 'pong'}
    mock_control = MagicMock()
    mock_control.inspect.return_value.ping.return_value = mock_ping
    celery = MagicMock()
    celery.control = mock_control

    result = celery_mod.check_online_status(celery)
    assert result == mock_ping


@patch("cve2stix.celery.check_online_status")
@patch("subprocess.Popen")
def test_start_celery_success(mock_popen, mock_check_online_status):
    # Simulate first few checks as None, then True
    mock_check_online_status.side_effect = [None, None, {'worker1': 'pong'}]

    process_mock = MagicMock()
    mock_popen.return_value = process_mock

    result = celery_mod.start_celery("cve2stix.celery")

    assert result == process_mock
    mock_popen.assert_called_with(
        ["celery", "-A", "cve2stix.celery", "--workdir", ".", "worker", "--loglevel", "info", "--purge"],
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    # Ensure we eventually got a successful ping
    mock_check_online_status.assert_called()


@patch("cve2stix.celery.check_online_status")
@patch("subprocess.Popen")
def test_start_celery_fails_after_retries(mock_popen, mock_check_online_status):
    mock_check_online_status.return_value = None
    process_mock = MagicMock()
    mock_popen.return_value = process_mock

    with pytest.raises(Exception, match="Unable to start worker"):
        celery_mod.start_celery("cve2stix.celery")

    process_mock.kill.assert_called_once()


@patch("cve2stix.main.fetch_data")
def test_cve_syncing_task_calls_fetch_data(mock_fetch_data):
    conf = {}
    celery_mod.cve_syncing_task("start_time", "end_time", conf)
    mock_fetch_data.assert_called_once()
    called_args = mock_fetch_data.call_args[0]
    assert called_args[0] == "start_time"
    assert called_args[1] == "end_time"
    assert isinstance(called_args[2], celery_mod.Config)


@patch("cve2stix.main.map_extensions")
@patch("cve2stix.main.map_default_objects")
@patch("cve2stix.celery.store_cve_in_bundle")
@pytest.mark.parametrize(
    "returns_vulnerabilities",
    [True, False]
)
def test_preparing_results_pipeline(
    mock_store_bundle,
    mock_defaults,
    mock_extensions,
    returns_vulnerabilities
):
    mock_defaults.return_value = ["m"]
    mock_extensions.return_value = ["e"]

    dummy_conf = {"file_system": "/tmp", "stix2_bundles_folder": "/tmp"}
    dummy_config = celery_mod.Config(**dummy_conf)

    with patch('stix2.FileSystemStore.query') as mock_query:
        mock_query.return_value = returns_vulnerabilities
        celery_mod.preparing_results(["results"], dummy_conf, "test.json")
        if returns_vulnerabilities:
            mock_query.call_count == 2
            mock_store_bundle.assert_called_once_with("/tmp", mock_query.return_value, "test.json")
        else:
            mock_query.assert_called_once()
            mock_store_bundle.assert_not_called()

    mock_defaults.assert_called_once()
    mock_extensions.assert_called_once()
