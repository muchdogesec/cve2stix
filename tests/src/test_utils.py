import pytest
from unittest.mock import MagicMock, call, patch
import requests
from cve2stix import utils

class DummyConfig:
    def __init__(self):
        self.results_per_page = 2
        self.nvd_api_key = "FAKE_KEY"

@pytest.fixture
def config():
    return DummyConfig()

@pytest.fixture
def callback():
    return MagicMock()

@patch('time.sleep')
def test_fetch_url_multiple_pages(mock_sleep, config, callback):
    responses = [
        MagicMock(),
        MagicMock(),
        MagicMock(),
    ]
    with patch("cve2stix.utils.fetch_nvd_api", return_value=responses) as mock_fetch:
        results = utils.fetch_url("https://nvd.nist.gov/api", config, callback)
    mock_fetch.assert_called_once_with("https://nvd.nist.gov/api", query=dict(resultsPerPage=2), api_key=config.nvd_api_key)

    assert len(results) == 3
    assert callback.call_count == 3
    callback.assert_has_calls([call(r, config) for r in responses])