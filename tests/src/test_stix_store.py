import json
import uuid
from pathlib import Path
import pytest
from stix2 import Vulnerability

from cve2stix import stix_store
from cve2stix.config import Config
from cve2stix.chunked_store import ChunkedFileSystemStore


@pytest.fixture
def cfg(tmp_path):
    return Config(
        file_system=str(tmp_path / "objects"),
        stix2_bundles_folder=str(tmp_path / "bundles"),
        chunk_per_part=2,
    )


def _make_vulnerabilities(identity_id, n=1):
    objs = []
    for i in range(n):
        objs.append(
            Vulnerability(
                id=f"vulnerability--{uuid.uuid4()}",
                created="2024-07-01T12:00:00Z",
                modified="2024-07-01T12:00:00Z",
                name=f"CVE-2024-{i:04d}",
                description="Example vulnerability",
                labels=["example"],
                created_by_ref=identity_id,
            )
        )
    return objs


def _populate(cfg, num_pages):
    """Simulate fetch: one chunk (== end_chunk call) per API page."""
    Path(cfg.file_system).mkdir(parents=True, exist_ok=True)
    identity_id = cfg.default_objects[0]["id"]
    store = ChunkedFileSystemStore(cfg.file_system, cfg.chunk_per_part)
    for _ in range(num_pages):
        store.add_all(_make_vulnerabilities(identity_id, 1))
        store.end_chunk()
    return ChunkedFileSystemStore.from_dir(cfg.file_system, cfg.chunk_per_part)


def test_single_part_writes_directory_with_meta(cfg):
    store = _populate(cfg, num_pages=1)
    result = stix_store.store_cve_in_bundle(
        cfg.stix2_bundles_folder, store, filename="data.json", cfg=cfg
    )

    out = Path(result["path"])
    assert out.is_dir()
    names = {p.name for p in out.iterdir()}
    assert names == {"meta.json", "bundle-001.json"}
    # no per-bundle meta files
    assert not any(n.endswith(".meta.json") for n in names)

    content = json.loads((out / "bundle-001.json").read_text())
    assert content["type"] == "bundle"


def test_multi_part_writes_directory_with_meta(cfg):
    # chunk_per_part=2, 5 pages -> ceil(5/2) = 3 parts
    store = _populate(cfg, num_pages=5)
    result = stix_store.store_cve_in_bundle(
        cfg.stix2_bundles_folder, store, filename="range.json", cfg=cfg
    )

    out = Path(result["path"])
    assert out.is_dir()

    names = {p.name for p in out.iterdir()}
    assert "meta.json" in names
    assert {"bundle-001.json", "bundle-002.json", "bundle-003.json"} <= names
    # per-bundle meta files must not be produced
    assert not any(n.endswith(".meta.json") for n in names)

    meta = json.loads((out / "meta.json").read_text())
    assert meta["total_bundles"] == 3
    assert meta["total_object_counts"].get("vulnerability") == 5
    assert [b["name"] for b in meta["bundles"]] == [
        "bundle-001.json",
        "bundle-002.json",
        "bundle-003.json",
    ]


def test_empty_range_still_writes_meta(cfg):
    # No pages processed -> no chunks -> no bundles, but meta.json is required.
    Path(cfg.file_system).mkdir(parents=True, exist_ok=True)
    store = ChunkedFileSystemStore.from_dir(cfg.file_system, cfg.chunk_per_part)
    result = stix_store.store_cve_in_bundle(
        cfg.stix2_bundles_folder, store, filename="empty.json", cfg=cfg
    )

    out = Path(result["path"])
    assert out.is_dir()
    names = {p.name for p in out.iterdir()}
    assert names == {"meta.json"}
    assert result["total_objects"] == 0
    assert result["bundles"] == []

    meta = json.loads((out / "meta.json").read_text())
    assert meta["total_bundles"] == 0
    assert meta["bundles"] == []


def test_bundle_includes_default_objects_and_extensions(cfg):
    store = _populate(cfg, num_pages=1)
    result = stix_store.store_cve_in_bundle(
        cfg.stix2_bundles_folder, store, filename="d.json", cfg=cfg
    )

    content = json.loads((Path(result["path"]) / "bundle-001.json").read_text())
    ids = {obj["id"] for obj in content["objects"]}
    # default objects
    assert {
        "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
        "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
        "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    } <= ids
    # extension definitions
    assert {
        "extension-definition--2c5c13af-ee92-5246-9ba7-0b958f8cd34a",
        "extension-definition--82cad0bb-0906-5885-95cc-cafe5ee0a500",
        "extension-definition--ec658473-1319-53b4-879f-488e47805554",
        "extension-definition--ad995824-2901-5f6e-890b-561130a239d4",
    } <= ids
