"""
Contains logic for storing parsed stix objects.
"""

import json
import os
import logging
from stix2 import FileSystemStore, Bundle
from stix2.datastore import DataSourceError
from .loggings import logger
from .config import Config
import uuid
from .helper import generate_md5_from_list
from uuid import UUID
from .config import DEFAULT_CONFIG as config


def store_cve_in_bundle(stix_bundle_path, stix_objects, filename=None):
    data = list(stix_objects)
    bundle_id = "bundle--" + str(uuid.uuid5(
        config.namespace,
        generate_md5_from_list(data)
        )
    )
    bundle_of_all_objects = Bundle(id=bundle_id, objects=data)

    # Create folder to store CVE
    os.makedirs(stix_bundle_path, exist_ok=True)

    stix_bundle_file = f"{stix_bundle_path}/cve-bundle.json"
    if filename:
        stix_bundle_file = f"{stix_bundle_path}/{filename}-cve-bundle.json"
        if filename.endswith(".json"):
            stix_bundle_file = f"{stix_bundle_path}/{filename}"
    
    logging.info("writing output to: %s", str(stix_bundle_file))
    with open(stix_bundle_file, "w") as f:
        f.write(json.dumps(json.loads(bundle_of_all_objects.serialize()), indent=4))

    return bundle_of_all_objects.id
