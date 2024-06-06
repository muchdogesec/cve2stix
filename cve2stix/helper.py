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


def store_new_cve(stix_store, parsed_response: CVE):
    stix_objects = (
        [
            parsed_response.vulnerability,
            parsed_response.indicator,
            parsed_response.identifies_relationship,
        ]
        + parsed_response.enrichment_attack_patterns
        + parsed_response.enrichment_relationships
        + parsed_response.softwares
    )

    status = stix_store.store_cve_in_bundle(
        parsed_response.vulnerability["name"], stix_objects
    )
    if status == False:
        return False

    stix_store.store_objects_in_filestore(stix_objects)
    return True


def update_existing_cve(existing_cve: CVE, stix_store, parsed_response):
    stix_objects = []
    try:
        vulnerability_dict = json.loads(parsed_response.vulnerability.serialize())
        vulnerability_dict.pop("type", None)
        vulnerability_dict.pop("created", None)
        vulnerability_dict.pop("id", None)
        vulnerability_dict.pop("created_by_ref", None)
        old_vulnerability = stix_store.get_object_by_id(
            existing_cve.vulnerability.id
        )
        new_vulnerability = new_version(old_vulnerability, **vulnerability_dict)
        stix_objects.append(new_vulnerability)

        if parsed_response.indicator != None:
            indicator_dict = json.loads(parsed_response.indicator.serialize())
            indicator_dict.pop("type", None)
            indicator_dict.pop("created", None)
            indicator_dict.pop("id", None)
            indicator_dict.pop("created_by_ref", None)

            old_indicator = None
            if existing_cve.indicator != None:
                old_indicator = stix_store.get_object_by_id(
                    existing_cve.indicator.id
                )

            new_indicator = parsed_response.indicator
            if old_indicator != None:
                new_indicator = new_version(old_indicator, **indicator_dict)
            stix_objects.append(new_indicator)

        if parsed_response.identifies_relationship != None:
            old_relationship = None
            if existing_cve.identifies_relationship != None:
                old_relationship = stix_store.get_object_by_id(
                    existing_cve.identifies_relationship.id
                )

            new_relationship = parsed_response.identifies_relationship
            if old_relationship != None:
                new_relationship = new_version(
                    old_relationship,
                    modified=pytz.UTC.localize(
                        parsed_response.vulnerability["modified"]
                    ),
                )
            stix_objects.append(new_relationship)

        stix_objects += parsed_response.enrichment_attack_patterns
        stix_objects += parsed_response.enrichment_relationships
        stix_objects += parsed_response.softwares

        stix_store.store_objects_in_filestore(stix_objects)
        stix_store.store_cve_in_bundle(
            parsed_response.vulnerability["name"], stix_objects, update=True
        )

    except InvalidValueError:
        logger.warning(
            "Tried updating %s, whose latest copy is already downloaded. Hence skipping it",
            parsed_response.vulnerability["name"],
        )


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

#
# def append_data(results):
#     config = Config()
#     for root, _, files in os.walk(config.file_system):
#         for filename in files:
#             if filename != "cve-bundle.json":
#                 file_path = os.path.join(root, filename)
#                 with open(file_path, "r") as file:
#                     stix_object = json.load(file)
#                     results.append(stix_object)
#     return results

def append_data(results, file_system):
    for root, _, files in os.walk(file_system):
        for filename in files:
            if filename != "cve-bundle.json":
                file_path = os.path.join(root, filename)
                with open(file_path, "rb") as file:
                    stix_object = json.load(file)
                    yield stix_object

def generate_md5_from_list(stix_objects: list) -> str:
    stix_objects = sorted(stix_objects, key=lambda obj: obj.get('id'))
    json_str = json.dumps(stix_objects, sort_keys=True).encode('utf-8')
    return hashlib.md5(json_str).hexdigest()


def cleanup(data):
    return [item for item in data if item != {}]