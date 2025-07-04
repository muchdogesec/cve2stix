import json
import os
from pathlib import Path
import pytest
from stix2 import Indicator, Vulnerability
from uuid import UUID

from cve2stix import stix_store


@pytest.fixture
def temp_output_dir(tmp_path):
    # tmp_path is a pytest built-in fixture
    return tmp_path


@pytest.fixture
def example_stix_objects():
    vuln = Vulnerability(
        id="vulnerability--cb8c264d-29af-4077-ac35-391dd1f146b7",
        created="2024-07-01T12:00:00Z",
        modified="2024-07-01T12:00:00Z",
        name="CVE-2024-0001",
        description="Example vulnerability",
        labels=["example"],
        created_by_ref="identity--abcdabcd-abcd-abcd-abcd-abcdabcdabcd",
        external_references=[],
        object_marking_refs=[],
    )
    indicator = Indicator(
        id="indicator--cb8c264d-29af-4077-ac35-391dd1f146b7",
        created="2024-07-01T12:00:00Z",
        modified="2024-07-01T12:00:00Z",
        name="Indicator for CVE-2024-0001",
        pattern="[file:name = 'file.txt']",
        pattern_type="stix",
        labels=["malicious-activity"],
        created_by_ref="identity--abcdabcd-abcd-abcd-abcd-abcdabcdabcd",
    )
    return [vuln, indicator]


def test_store_creates_bundle_file(temp_output_dir, example_stix_objects):
    bundle_id = stix_store.store_cve_in_bundle(str(temp_output_dir), example_stix_objects)

    # Expect default filename
    expected_file = temp_output_dir / "cve-bundle.json"
    assert expected_file.exists()

    # Check valid UUID
    assert bundle_id.startswith("bundle--")
    UUID(bundle_id[8:])  # raises ValueError if not a valid UUID

    # Check file content is valid JSON and contains our objects
    content = json.loads(expected_file.read_text())
    assert content["type"] == "bundle"
    assert len(content["objects"]) == 2
    ids = {obj["id"] for obj in content["objects"]}
    assert "vulnerability--cb8c264d-29af-4077-ac35-391dd1f146b7" in ids


def test_store_with_filename_creates_named_file(temp_output_dir, example_stix_objects):
    bundle_id = stix_store.store_cve_in_bundle(str(temp_output_dir), example_stix_objects, filename="myfile")

    expected_file = temp_output_dir / "myfile-cve-bundle.json"
    assert expected_file.exists()

    content = json.loads(expected_file.read_text())
    assert content["type"] == "bundle"


def test_store_with_json_filename_removes_extra_suffix(temp_output_dir, example_stix_objects):
    bundle_id = stix_store.store_cve_in_bundle(str(temp_output_dir), example_stix_objects, filename="data.json")

    expected_file = temp_output_dir / "data.json"
    assert expected_file.exists()

    content = json.loads(expected_file.read_text())
    assert content["type"] == "bundle"


def test_store_returns_correct_bundle_id(temp_output_dir, example_stix_objects):
    bundle_id = stix_store.store_cve_in_bundle(str(temp_output_dir), example_stix_objects)
    assert bundle_id.startswith("bundle--")
    # Should be a valid UUID5 (deterministic, so repeated call with same data = same id)
    uuid_obj = UUID(bundle_id[8:])
    assert uuid_obj.version == 5

