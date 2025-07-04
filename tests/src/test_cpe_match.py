from datetime import datetime
import random
from unittest.mock import patch

import pytest
from stix2 import Software, Indicator, Relationship
from pytz import timezone
from cve2stix import cpe_match


def test_get_cpe_match():
    with patch('cve2stix.cpe_match.retrieve_cpematch') as mock_retrieve_cpematch:
        mock_retrieve_cpematch.return_value = {'match1': ['match2', 'match3']}
        cpe_match.get_cpe_match('match1') == ['match2', 'match3']
        cpe_match.get_cpe_match('match4') == ['match4']


def test_unescape_cpe_string_returns_same_string():
    val = cpe_match.unescape_cpe_string("cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*")
    assert isinstance(val, str)
    assert "cpe:2.3:" in val


@pytest.mark.parametrize("cpename, expected_split", [
    ("cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*", 
     ["cpe", "2.3", "a", "apache", "http_server", "2.4.1", "*", "*", "*", "*", "*", "*", "*"]),
    ("cpe:2.3:a:microsoft:windows\\:server:2019:*:*:*:*:*:*:*",
     ["cpe", "2.3", "a", "microsoft", "windows\\:server", "2019", "*", "*", "*", "*", "*", "*", "*"])
])
def test_split_cpe_name(cpename, expected_split):
    split = cpe_match.split_cpe_name(cpename)
    assert split == expected_split


def test_cpe_name_as_dict_extracts_fields():
    cpe = "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"
    d = cpe_match.cpe_name_as_dict(cpe)
    assert d == {
        "cpe_version": "2.3",
        "part": "a",
        "vendor": "apache",
        "product": "http_server",
        "version": "2.4.1",
        "update": "*",
        "edition": "*",
        "language": "*",
        "sw_edition": "*",
        "target_sw": "*",
        "target_hw": "*",
        "other": "*",
    }


def test_parse_software_returns_valid_software():
    cpe = "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"
    swid = "software--12345"
    software_obj = cpe_match.parse_software(cpe, swid)
    assert isinstance(software_obj, Software)
    assert software_obj.x_cpe_struct == cpe_match.cpe_name_as_dict(cpe)
    assert software_obj.name == cpe
    assert software_obj.cpe == cpe
    assert software_obj.version == "2.4.1"
    assert software_obj.vendor == software_obj.x_cpe_struct['vendor']
    assert swid == software_obj.swid
    assert cpe_match.software_cpe_properties_ExtensionDefinitionSMO.id in software_obj.extensions


@pytest.fixture
def indicator_with_cpes():
    return Indicator(
        name="CVE-2024-0001",
        pattern="fake sigma pattern",
        pattern_type='sigma',
        created="2024-01-01T00:00:00Z",
        modified="2024-01-01T00:00:00Z",
        id="indicator--fa0207be-9399-4b02-990b-fb3b64bf37ef",
        created_by_ref="identity--fa0207be-9399-4b02-990b-fb3b64bf37ef",
        object_marking_refs=["marking-definition--fa0207be-9399-4b02-990b-fb3b64bf37ef"],
        x_cpes={
            "vulnerable": [
                {"criteria": "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*", "matchCriteriaId": "266d432e-20ae-4bab-a175-83255f2d859e"}
            ],
            "not_vulnerable": [
                {"criteria": "cpe:2.3:a:nginx:nginx:1.20.1:*:*:*:*:*:*:*", "matchCriteriaId": "BBBECC06-F3D5-4B63-8EB2-8E44A64624C5"}
            ]
        },
        extensions={
            "extension-definition--fa0207be-9399-4b02-990b-fb3b64bf37ef": {
                "extension_type": "toplevel-property-extension"
            }
        }
    )


def test_parse_cpe_matches_returns_softwares_and_relationships(indicator_with_cpes):
    with patch("cve2stix.cpe_match.retrieve_cpematch") as mock_retrieve_cpematch:
        mock_retrieve_cpematch.return_value = {
            "cpe:2.3:a:nginx:nginx:1.20.1:*:*:*:*:*:*:*": [
                "cpe:2.3:a:nginx:nginx:1.20.1:*:*:en:*:*:*:*",
                "cpe:2.3:a:nginx:nginx:1.20.1:*:*:es:*:*:*:*",
            ],
        }
        softwares, relationships = cpe_match.parse_cpe_matches(indicator_with_cpes)

    software_cpes = {s.id: s.cpe for s in softwares}
    assert "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*" in software_cpes.values()
    assert "cpe:2.3:a:nginx:nginx:1.20.1:*:*:*:*:*:*:*" not in software_cpes.values()
    assert "cpe:2.3:a:nginx:nginx:1.20.1:*:*:en:*:*:*:*" in software_cpes.values()
    assert "cpe:2.3:a:nginx:nginx:1.20.1:*:*:es:*:*:*:*" in software_cpes.values()
    software_rels = [
        (s.source_ref, s.target_ref, s.relationship_type, s.description)
        for s in relationships
    ]
    assert software_rels == [
        (
            "indicator--fa0207be-9399-4b02-990b-fb3b64bf37ef",
            "software--f5c284f6-3ad9-5131-bc61-8824a9ecf64b",
            "relies-on",
            "CVE-2024-0001 relies on cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*",
        ),
        (
            "indicator--fa0207be-9399-4b02-990b-fb3b64bf37ef",
            "software--f5c284f6-3ad9-5131-bc61-8824a9ecf64b",
            "exploits",
            "CVE-2024-0001 exploits cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*",
        ),
        (
            "indicator--fa0207be-9399-4b02-990b-fb3b64bf37ef",
            "software--abf60c79-f6ee-524e-8226-5c5435777f2d",
            "relies-on",
            "CVE-2024-0001 relies on cpe:2.3:a:nginx:nginx:1.20.1:*:*:en:*:*:*:*",
        ),
        (
            "indicator--fa0207be-9399-4b02-990b-fb3b64bf37ef",
            "software--1c0b8917-621b-5f2b-977c-0e7b07720ee5",
            "relies-on",
            "CVE-2024-0001 relies on cpe:2.3:a:nginx:nginx:1.20.1:*:*:es:*:*:*:*",
        ),
    ]
    for relationship in relationships:
        assert relationship.created_by_ref == indicator_with_cpes.created_by_ref
        assert (
            relationship.object_marking_refs == indicator_with_cpes.object_marking_refs
        )
        # assert indicator_with_cpes.external_references[0] in relationship.external_references
        assert {
            "source_name": "cpe",
            "external_id": software_cpes[relationship.target_ref],
        } in relationship.external_references
        assert {
            "source_name": "cve",
            "external_id": "CVE-2024-0001",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        } in relationship.external_references


def test_parse_cpe_matches_empty_for_none():
    softwares, relationships = cpe_match.parse_cpe_matches(None)
    assert softwares == []
    assert relationships == []


def test_retrieve_cpe_match():
    retval = cpe_match.retrieve_cpematch(datetime.now(timezone('EST')).date())
    assert len(retval) > 10_000
    assert isinstance(retval, dict)
    random_matches = random.choice(list(retval.values()))
    assert isinstance(random_matches, list)

