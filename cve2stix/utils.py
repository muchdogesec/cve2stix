import json
import re
from .loggings import logger
from urllib.parse import parse_qs, urlparse, urlunparse, parse_qsl, urlencode
import math
import requests
import time
from stix2.patterns import StringConstant


def fetch_url(url, config, callback):
    total_results = math.inf
    start_index = 0
    backoff_time = 10
    all_responses_content = []
    uri = urlparse(url)
    query = dict(parse_qsl(uri.query))

    while start_index < total_results:
        logger.info(f"Calling NVD API `{uri.path}` with startIndex: {start_index}", )
        query.update({
            "resultsPerPage": config.results_per_page,
            "startIndex": start_index
        })

        try:
            logger.info(f"Query => {query}")
            response = requests.get(url, query, headers=dict(apiKey=config.nvd_api_key))
            logger.info(f"URL => {response.url}")
            logger.info(f"HEADERS => {response.request.headers}")
            logger.info(f"Status Code => {response.status_code} [{response.reason}]")
            if response.status_code != 200:
                logger.warning("Got response status code %d.", response.status_code)
                raise requests.ConnectionError

        except requests.ConnectionError as ex:
            logger.warning(
                "Got ConnectionError. Backing off for %d seconds.", backoff_time
            )
            time.sleep(backoff_time)
            backoff_time *= 1.5
            continue

        content = response.json()
        all_responses_content.append(content)
        total_results = content["totalResults"]
        logger.info(f"Total Results {total_results}")
        if callback:
            response = callback(content, config)

        start_index += content["resultsPerPage"]
        if start_index < total_results:
            time.sleep(5)
        backoff_time = 10
    return all_responses_content


def unescape_cpe_string(cpe_string):
    return str(StringConstant(cpe_string))