"""
Miscellaneous helper functions
"""

import os
import shutil
import hashlib
import json
from stix2 import new_version
from stix2.exceptions import InvalidValueError
import logging
import shutil
import pytz
from .cve import CVE
from .config import Config
from .loggings import logger
from stix2.serialization import serialize as stix_serialize


def get_date_string_nvd_format(date):
    return date.strftime("%Y-%m-%dT%H:%M:%SZ")

def clean_filesystem(default_path=None):
    config = Config()
    logging.info("Deleting old data from filesystem")
    path = default_path if default_path else config.file_system
    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            logging.error(f"Failed to delete {file_path}. Reason: {e}")
    logging.info("Deletion done!")

def generate_md5_from_list(stix_objects: list) -> str:
    stix_objects = sorted(stix_objects, key=lambda obj: obj.get('id'))
    json_str = stix_serialize(stix_objects).encode('utf-8')
    return hashlib.md5(json_str).hexdigest()
