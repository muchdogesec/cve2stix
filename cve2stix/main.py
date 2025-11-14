"""
Main driver logic for cve2stix
"""

import dataclasses
import sys
import pytz
from datetime import datetime, timedelta, date

from .config import Config
from .helper import get_date_string_nvd_format, clean_filesystem
from .cve import parse_cve_api_response
from stix2 import parse
from celery import group, chord
from .celery import cve_syncing_task, preparing_results
from .loggings import logger
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from .utils import fetch_url
from stix2extensions.definitions.properties import VulnerabilityOpenCTIPropertiesExtension, VulnerabilityScoringExtension, IndicatorVulnerableCPEPropertyExtension, SoftwareCpePropertiesExtension

sys.setrecursionlimit(10000)


def fetch_data(start, end, config: Config):
    uri = list(urlsplit(config.nvd_cve_api_endpoint))
    uri[3] = urlencode(
        parse_qsl(uri[3])
        + [
            (config.filter_mode + "StartDate", get_date_string_nvd_format(start)),
            (config.filter_mode + "EndDate", get_date_string_nvd_format(end)),
        ]
    )
    return fetch_url(urlunsplit(uri), config, parse_cve_api_response)


def map_default_objects(config: Config, object_list: list):
    logger.info("Add Marking definition objects to bundle: START")
    object_list.extend(config.default_objects)
    config.fs.add(config.default_objects)
    logger.info("Add Marking definition objects to bundle: DONE")
    return object_list


def map_extensions(config: Config, object_list: list):
    logger.info("Adding extensions")
    extensions = [
        VulnerabilityScoringExtension.extension_definition,
        VulnerabilityOpenCTIPropertiesExtension.extension_definition,
        IndicatorVulnerableCPEPropertyExtension.extension_definition,
        SoftwareCpePropertiesExtension.extension_definition
    ]
    object_list.extend(extensions)
    config.fs.add(extensions)
    return object_list


def _parse_date(d: str | datetime | date):
    if isinstance(d, str):
        d = pytz.utc.localize(datetime.strptime(d, "%Y-%m-%dT%H:%M:%S"))
    elif isinstance(d, datetime):
        d = d.replace(tzinfo=d.tzinfo or pytz.utc)
    elif isinstance(d, date):
        d = datetime(d.year, d.month, d.day, tzinfo=pytz.utc)
    return d


def main(c_start_date=None, c_end_date=None, filename=None, config=Config()):

    clean_filesystem(config.file_system)
    params = []
    current_date = _parse_date(config.start_date)
    if c_start_date:
        current_date = _parse_date(c_start_date)

    end_date_ = _parse_date(config.end_date)
    if c_end_date:
        end_date_ = _parse_date(c_end_date)

    while current_date < end_date_:
        start_date = current_date
        end_date = current_date + timedelta(days=120)
        if end_date > end_date_:
            end_date = end_date_
        params.append([start_date, end_date])
        current_date = end_date

    tasks = [
        cve_syncing_task.s(param[0], param[1], dataclasses.asdict(config))
        for param in params
    ]
    res = chord(group(tasks))(preparing_results.s(dataclasses.asdict(config), filename))
    resp = res.get()
    return resp
