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


def get_date_string_nvd_format(date):
    return date.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json_file(filename, data_folder="data/stix_templates/", include_filepath=False):
    config = Config()
    path = filename
    if not include_filepath:
        path = os.path.join("{}/{}".format(config.data_path, data_folder), filename)
    return json.load(open(path))

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

def write_file_to_folder(folder_path, file_name, content):
    file_path = os.path.join(folder_path, file_name)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    with open(file_path, 'w') as file:
        json.dump(content, file)


def delete_directory(directory_path):
    try:
        shutil.rmtree(directory_path)
        logger.info(f"Directory {directory_path} has been deleted.")
    except FileNotFoundError:
        logger.error(f"Directory {directory_path} does not exist.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")


def delete_subfolders(directory_path, ignore_extension='.json'):
    for root, dirs, files in os.walk(directory_path, topdown=False):
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            shutil.rmtree(dir_path)

def append_data(results, file_system):
    for root, _, files in os.walk(file_system):
        for filename in files:
            if filename != "cve-bundle.json":
                file_path = os.path.join(root, filename)
                with open(file_path, "rb") as file:
                    try:
                        yield json.load(file)
                    except Exception  as e:
                        logger.info(f"append_data: skipping unprocessable file at {file_path}")

def generate_md5_from_list(stix_objects: list) -> str:
    stix_objects = sorted(stix_objects, key=lambda obj: obj.get('id'))
    json_str = json.dumps(stix_objects, sort_keys=True).encode('utf-8')
    return hashlib.md5(json_str).hexdigest()


def cleanup(data):
    return [item for item in data if item != {}]