"""
Contains logic for storing parsed stix objects as chunked bundles.
"""

import json
import logging
from pathlib import Path
from collections import defaultdict

from .chunked_store import ChunkedFileSystemStore


def _bundle_base_path(stix_bundle_path, filename):
    """Resolve the output directory for a time range."""
    relative = filename or "cve-bundle"
    if relative.endswith(".json"):
        relative = relative[: -len(".json")]
    return Path(stix_bundle_path) / relative


def _write_bundle(bundle, path):
    logging.info(f"writing output to: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(json.dumps(json.loads(bundle.serialize()), indent=4))


def _count_by_type(objects):
    counts = defaultdict(int)
    for obj in objects:
        counts[obj["type"]] += 1
    return dict(counts)


def store_cve_in_bundle(stix_bundle_path, store, filename=None, cfg=None):
    """Group the store's chunks into parts and write one bundle per part.

    Every time range is written as a directory `<base>/` holding one
    `bundle-{n}.json` per part and an aggregate `meta.json`. The `meta.json`
    is always written, even when the range produced no objects.
    Returns a dict describing what was written.
    """
    chunks = store.get_chunks_info()
    chunk_per_part = cfg.chunk_per_part
    parts = [
        chunks[i : i + chunk_per_part]
        for i in range(0, len(chunks), chunk_per_part)
    ]

    base = _bundle_base_path(stix_bundle_path, filename)
    base.mkdir(parents=True, exist_ok=True)

    total_object_counts = defaultdict(int)
    bundle_manifests = []

    for part_number, part in enumerate(parts, start=1):
        objects = store.read_chunk_objects(part)
        bundle = ChunkedFileSystemStore.make_bundle(objects, cfg)
        object_counts = _count_by_type(bundle.objects)

        bundle_name = f"bundle-{part_number:03d}.json"
        _write_bundle(bundle, base / bundle_name)

        for obj_type, count in object_counts.items():
            total_object_counts[obj_type] += count
        bundle_manifests.append(
            {
                "name": bundle_name,
                "number": part_number,
                "id": bundle.id,
                "object_counts": object_counts,
            }
        )

    meta_data = {
        "total_bundles": len(bundle_manifests),
        "total_objects": sum(total_object_counts.values()),
        "total_object_counts": dict(total_object_counts),
        "bundles": bundle_manifests,
    }
    meta_file = base / "meta.json"
    logging.info(f"writing metadata to: {meta_file}")
    with open(meta_file, "w") as f:
        json.dump(meta_data, f, indent=4)

    return {
        "path": str(base),
        "bundles": [manifest["name"] for manifest in bundle_manifests],
        "total_objects": meta_data["total_objects"],
    }
