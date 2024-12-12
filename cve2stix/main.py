"""
Main driver logic for cve2stix
"""

import dataclasses
import math
import requests
import time
from datetime import datetime, timedelta, date

from .config import Config
from .helper import (
    get_date_string_nvd_format, load_json_file, clean_filesystem
)
from .parse_api_response import parse_cve_api_response
from stix2 import parse
from celery import group, chord
from .celery import cve_syncing_task, preparing_results
from .loggings import logger
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, urlsplit, urlunsplit
from .utils import fetch_url
from stix2extensions import _extensions as stix_extensions


def fetch_data(start, end, config):
    uri = list(urlsplit(config.nvd_cve_api_endpoint))
    uri[3] = urlencode(parse_qsl(uri[3]) + [("lastModStartDate", get_date_string_nvd_format(start)), ("lastModEndDate", get_date_string_nvd_format(end))])
    return fetch_url(urlunsplit(uri), config, parse_cve_api_response)


def map_marking_definition(config, object_list):
    logger.info("Marking Definition creation start")
    marking_definition = parse(config.CVE2STIX_MARKING_DEFINITION_REF)
    object_list.append(marking_definition)
    config.fs.add(marking_definition)
    logger.info("Marking Definition creation end")
    return object_list

def map_extensions(config, object_list):
    logger.info("Adding extensions")
    extensions = [stix_extensions.indicator_vulnerable_cpes_ExtensionDefinitionSMO, stix_extensions.vulnerability_scoring_ExtensionDefinitionSMO, stix_extensions.software_cpe_properties_ExtensionDefinitionSMO]
    object_list.extend(extensions)
    config.fs.add(extensions)
    return object_list

def map_identity(config, object_list):
    logger.info("Marking Identity creation start")
    identity = parse(config.CVE2STIX_IDENTITY_REF)
    object_list.append(identity)
    config.fs.add(identity)
    logger.info("Marking Identity creation end")
    return object_list

def _parse_date(d: str|datetime|date):
    if isinstance(d, str):
        d = datetime.strptime(d, "%Y-%m-%dT%H:%M:%S")
    elif isinstance(d, date):
        d = datetime.fromtimestamp(d.timestamp())
    return d

def main(c_start_date=None, c_end_date=None, filename=None, config = Config()):
    
    clean_filesystem(config.file_system)
    params = []
    current_date = _parse_date(config.start_date)
    if c_start_date:
        current_date = _parse_date(c_start_date)

    end_date_ = _parse_date(config.end_date)
    if c_start_date:
        end_date_ = _parse_date(c_end_date)

    while current_date < end_date_:
        start_date = current_date
        end_date = current_date + timedelta(days=120)
        if end_date > end_date_:
            end_date = end_date_
        params.append(
            [start_date, end_date]
        )
        current_date = end_date

    tasks = [cve_syncing_task.s(param[0], param[1], dataclasses.asdict(config)) for param in params]
    res = chord(group(tasks))(preparing_results.s(dataclasses.asdict(config), filename))
    resp = res.get()
    return resp

