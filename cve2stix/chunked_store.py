"""
Wrapper around FileSystemStore to track chunks of objects.
"""

import contextlib
import json
import os
import uuid
import logging
from pathlib import Path
from stix2 import FileSystemStore, Bundle
from stix2.serialization import fp_serialize
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from stix2.datastore import DataSourceError


class ChunkedFileSystemStore:
    """Wraps FileSystemStore to track chunks of objects."""

    def __init__(self, file_system_path: str, chunk_per_part: int = 10):
        self.file_system_path = file_system_path
        self.chunk_per_part = chunk_per_part
        self._chunk_id = 0
        self._chunk_file_path = None
        self._current_chunk_objects = []
        self._current_chunk_counts = defaultdict(int)
        self._all_chunks = []
        self._initialize_chunk()

    @classmethod
    def from_dir(cls, file_system_path: str, chunk_per_part: int = 10):
        """Load previously written chunk manifests from an existing directory."""
        store = cls(file_system_path, chunk_per_part)
        store._all_chunks = []
        for chunk_file in sorted(Path(file_system_path).glob("chunk-*.json")):
            with open(chunk_file) as f:
                store._all_chunks.append(json.load(f))
        return store

    def _initialize_chunk(self):
        """Initialize a new chunk file."""
        self._chunk_id += 1
        self._chunk_file_path = os.path.join(
            self.file_system_path, f"chunk-{self._chunk_id:06d}.json"
        )
        self._current_chunk_objects = []
        self._current_chunk_counts = defaultdict(int)

    def add(self, obj):
        """Add object to store and track in current chunk."""
        self._current_chunk_objects.append(obj['id'])
        self._current_chunk_counts[obj['type']] += 1
        self.write_object_to_store(obj)

    def get_file_path_for_object(self, object_id):
        """Return the file path for a given object id."""
        object_type = object_id.split("--", 1)[0]
        return os.path.join(self.file_system_path, object_type, f"{object_id}.json")

    def write_object_to_store(self, obj):
        path = self.get_file_path_for_object(obj['id'])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            fp_serialize(obj, f, indent=4)

    def add_all(self, objs):
        """Add multiple objects to store."""
        for obj in objs:
            self.add(obj)

    def end_chunk(self):
        """Finalize current chunk and write to file."""
        if not self._current_chunk_objects:
            return

        chunk_data = {
            "chunk_id": self._chunk_id,
            "objects": self._current_chunk_objects,
            "object_counts": dict(self._current_chunk_counts),
        }

        os.makedirs(self.file_system_path, exist_ok=True)
        with open(self._chunk_file_path, "w") as f:
            json.dump(chunk_data, f)

        logging.info(
            f"Chunk {self._chunk_id} finalized: {len(self._current_chunk_objects)} objects"
        )

        self._all_chunks.append(
            {
                "chunk_id": self._chunk_id,
                "chunk_file": self._chunk_file_path,
                "object_count": len(self._current_chunk_objects),
                "object_counts": dict(self._current_chunk_counts),
            }
        )

        self._initialize_chunk()

    def get_chunks_info(self):
        """Return information about all chunks processed."""
        return self._all_chunks

    def read_object(self, object_id):
        """Read a single object back from disk by its id."""
        path = self.get_file_path_for_object(object_id)
        with open(path) as f:
            return json.load(f)
        
    def get_chunk_objects_id(self, chunks):
        """Return the object ids referenced by a chunk or list of chunks."""
        if isinstance(chunks, dict):
            chunks = [chunks]
        seen = set()
        object_ids = []
        for chunk in chunks:
            for object_id in chunk["objects"]:
                if object_id in seen:
                    continue
                seen.add(object_id)
                object_ids.append(object_id)
        return object_ids

    def read_chunk_objects(self, chunks, max_workers=32):
        """Return the full objects referenced by a chunk or list of chunks.

        The same object id (e.g. a CNA identity) can be referenced by several
        chunks; it is stored once on disk, so it is returned once here. Files
        are read concurrently in a thread pool, as a part may reference hundreds
        of thousands of objects.
        """
        object_ids = self.get_chunk_objects_id(chunks)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # map preserves the order of object_ids.
            return list(executor.map(self.read_object, object_ids))

    @staticmethod
    def make_bundle(objects, config):
        """Create a STIX Bundle from `objects`, adding default objects + extensions."""
        from stix2extensions.definitions.properties import (
            VulnerabilityOpenCTIPropertiesExtension,
            VulnerabilityScoringExtension,
            IndicatorVulnerableCPEPropertyExtension,
            SoftwareCpePropertiesExtension,
        )
        from .helper import generate_md5_from_list

        extensions = [
            VulnerabilityScoringExtension.extension_definition,
            VulnerabilityOpenCTIPropertiesExtension.extension_definition,
            IndicatorVulnerableCPEPropertyExtension.extension_definition,
            SoftwareCpePropertiesExtension.extension_definition,
        ]
        all_objects = (
            list(config.default_objects)
            + [json.loads(extension.serialize()) for extension in extensions]
            + list(objects)
        )
        bundle_id = "bundle--" + str(
            uuid.uuid5(config.namespace, generate_md5_from_list(all_objects))
        )
        return Bundle(id=bundle_id, objects=all_objects, allow_custom=True)
