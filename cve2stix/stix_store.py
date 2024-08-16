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


def get_first_item_safely(list):
    if list != None and len(list) > 0:
        return list[0]
    return None


class StixStore:
    """
    Interface for handling storing and getting STIX objects
    """

    def __init__(self, file_store_path, bundle_path):
        if os.path.exists(file_store_path) == False:
            os.makedirs(file_store_path)
        self.file_store_path = file_store_path
        self.stix_file_store = FileSystemStore(file_store_path, allow_custom=True)

        if os.path.exists(bundle_path) == False:
            os.makedirs(bundle_path)
        self.stix_bundle_path = bundle_path

    def store_objects_in_filestore(self, stix_objects):
        for stix_object in stix_objects:
            self.store_object_in_filestore(stix_object)

    def store_object_in_filestore(self, stix_object):
        if stix_object == None:
            logger.debug("Tried storing None object in store, ignoring it..")
            return
        try:
            self.stix_file_store.add(stix_object)
        except DataSourceError as ex:
            # Ignoring error, since it occurs when file is already
            # present in the file store, which is OK
            if hasattr(stix_object, "id"):
                logger.debug(
                    "Exception caught while storing stix object %s: %s",
                    stix_object.id,
                    ex,
                )
            else:
                logger.debug(
                    "Exception caught while storing stix object %s: %s",
                    stix_object,
                    ex,
                )

    def store_cve_in_bundle(self, stix_objects, filename=None, update=False):
        from uuid import UUID
        data = list(stix_objects)
        bundle_id = "bundle--" + str(uuid.uuid5(
            UUID('162e1800-92bd-573c-abbd-f359594ffad9'),
            generate_md5_from_list(data)
            ))
        bundle_of_all_objects = Bundle(id=bundle_id, objects=data)

        # Create folder to store CVE
        os.makedirs(self.stix_bundle_path, exist_ok=True)

        stix_bundle_file = f"{self.stix_bundle_path}/cve-bundle.json"
        if filename:
            stix_bundle_file = f"{self.stix_bundle_path}/{filename}-cve-bundle.json"
            if filename.endswith(".json"):
                stix_bundle_file = f"{self.stix_bundle_path}/{filename}"
        
        if os.path.isfile(stix_bundle_file) and update == False:
            return None
        logging.info("writing output to: %s", str(stix_bundle_file))
        with open(stix_bundle_file, "w") as f:
            f.write(json.dumps(json.loads(bundle_of_all_objects.serialize()), indent=4))

        return bundle_of_all_objects.id
