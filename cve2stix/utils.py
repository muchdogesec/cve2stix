from stix2.patterns import StringConstant
from arango_cve_processor.tools.nvd import fetch_nvd_api


def fetch_url(url, config, callback, ratelimit_window=30):
    all_responses_content = []
    for data in fetch_nvd_api(url, query=dict(resultsPerPage=config.results_per_page), api_key=config.nvd_api_key):
        if callable(callback):
            callback(data, config)
        all_responses_content.append(data)
    return all_responses_content

def make_stix_pattern_string(cpe_string):
    return str(StringConstant(cpe_string))
