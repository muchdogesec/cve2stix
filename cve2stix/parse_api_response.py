import contextlib
from datetime import datetime
import re
import uuid
import sys
import json
import time
import requests
from stix2 import Vulnerability, Indicator, Relationship, Report
from typing import List

from .config import Config
from .helper import cleanup
from .loggings import logger
from .cve import CVE
from .utils import fetch_url, unescape_cpe_string
from stix2extensions._extensions import indicator_vulnerable_cpes_ExtensionDefinitionSMO, vulnerability_scoring_ExtensionDefinitionSMO
from stix2.datastore import DataSourceError
sys.setrecursionlimit(10000)

  
def parse_cve_api_response(
    cve_content, config: Config) -> List[CVE]:
    parsed_response = []
    for cve_item in cve_content["vulnerabilities"]:
        cve = CVE.from_dict(cve_item)
        logger.info(f"CVE-> {cve.name}")
        for object in cve.objects:
            with contextlib.suppress(DataSourceError):
                config.fs.add(object)
    return parsed_response
