import pytest
from unittest.mock import MagicMock, patch
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

def make_fake_response(json_data, url="https://nvd.nist.gov/api", headers=None):
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.reason = "OK"
    fake_resp.url = url
    fake_resp.request.headers = headers or {}
    fake_resp.json.return_value = json_data
    return fake_resp

def test_fetch_url_single_page(config, callback):
    json_data = {"totalResults": 2, "resultsPerPage": 2}
    with patch("requests.get", return_value=make_fake_response(json_data)) as mock_get:
        results = utils.fetch_url("https://nvd.nist.gov/api", config, callback)

    assert len(results) == 1
    callback.assert_called_once()
    mock_get.assert_called_once()
    called_args = mock_get.call_args[1]
    assert called_args["headers"]["apiKey"] == config.nvd_api_key

@patch('time.sleep')
def test_fetch_url_multiple_pages(mock_sleep, config, callback):
    responses = [
        make_fake_response({"totalResults": 4, "resultsPerPage": 2}),
        make_fake_response({"totalResults": 4, "resultsPerPage": 2}),
    ]
    with patch("requests.get", side_effect=responses) as mock_get:
        results = utils.fetch_url("https://nvd.nist.gov/api", config, callback)

    assert len(results) == 2
    assert callback.call_count == 2
    assert mock_get.call_count == 2

@patch('time.sleep')
def test_fetch_url_connection_error(mock_sleep, config, callback):
    responses = [
        requests.ConnectionError(),  # fail first
        make_fake_response({"totalResults": 2, "resultsPerPage": 2})  # then succeed
    ]
    with patch("requests.get", side_effect=responses) as mock_get:
        results = utils.fetch_url("https://nvd.nist.gov/api", config, callback)

    assert len(results) == 1
    callback.assert_called_once()
    assert mock_get.call_count == 2

@patch('time.sleep')
def test_fetch_url_retries_multiple_times(mock_sleep, config, callback):
    responses = [
        requests.ConnectionError(),
        requests.ConnectionError(),
        make_fake_response({"totalResults": 2, "resultsPerPage": 2})
    ]
    with patch("requests.get", side_effect=responses) as mock_get:
        results = utils.fetch_url("https://nvd.nist.gov/api", config, callback)

    assert len(results) == 1
    assert callback.call_count == 1
    assert mock_get.call_count == 3
