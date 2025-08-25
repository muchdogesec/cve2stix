from datetime import datetime
import random
from unittest.mock import patch

import pytest
from stix2 import Software, Indicator, Relationship
from pytz import timezone
from cve2stix import cpe_match

def test_unescape_cpe_string_returns_same_string():
    val = cpe_match.unescape_cpe_string(
        "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"
    )
    assert isinstance(val, str)
    assert "cpe:2.3:" in val


@pytest.mark.parametrize(
    "cpename, expected_split",
    [
        (
            "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*",
            [
                "cpe",
                "2.3",
                "a",
                "apache",
                "http_server",
                "2.4.1",
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
            ],
        ),
        (
            "cpe:2.3:a:microsoft:windows\\:server:2019:*:*:*:*:*:*:*",
            [
                "cpe",
                "2.3",
                "a",
                "microsoft",
                "windows\\:server",
                "2019",
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
            ],
        ),
    ],
)
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
    assert software_obj.vendor == software_obj.x_cpe_struct["vendor"]
    assert swid == software_obj.swid
    assert (
        cpe_match.software_cpe_properties_ExtensionDefinitionSMO.id
        in software_obj.extensions
    )


@pytest.fixture
def indicator_with_cpes():
    return Indicator(
        **{
            "created": "2010-04-01T22:30:00.360Z",
            "created_by_ref": "identity--562918ee-d5da-5579-b6a1-fae50cc6bad3",
            "description": 'The HTTP client functionality in Apple iPhone OS 3.1 on the iPhone 2G and 3.1.3 on the iPhone 3GS allows remote attackers to cause a denial of service (Safari, Mail, or Springboard crash) via a crafted innerHTML property of a DIV element, related to a "malformed character" issue.',
            "extensions": {
                "extension-definition--ad995824-2901-5f6e-890b-561130a239d4": {
                    "extension_type": "toplevel-property-extension"
                }
            },
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2010-1226",
                    "external_id": "CVE-2010-1226",
                }
            ],
            "id": "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "indicator_types": ["compromised"],
            "modified": "2025-04-11T00:51:21.963Z",
            "name": "CVE-2010-1226",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
            ],
            "pattern": "([software:cpe='cpe:2.3:h:apple:iphone:2g:*:*:*:*:*:*:*'] AND [software:cpe='cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:*:*:*']) OR ([software:cpe='cpe:2.3:h:apple:iphone:3gs:*:*:*:*:*:*:*'] AND [software:cpe='cpe:2.3:o:apple:iphone_os:3.1.3:*:*:*:*:*:*:*'])",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2010-04-01T22:30:00.36Z",
            "x_cpes": {
                "not_vulnerable": [
                    {
                        "criteria": "cpe:2.3:h:apple:iphone:2g:*:*:*:*:*:*:*",
                        "matchCriteriaId": "B340EF28-D584-4A2B-B0BD-E2E99142C36D",
                    },
                    {
                        "criteria": "cpe:2.3:h:apple:iphone:3gs:*:*:*:*:*:*:*",
                        "matchCriteriaId": "4926A18C-399F-490A-9CCD-F91C3062F278",
                    },
                ],
                "vulnerable": [
                    {
                        "criteria": "cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:*:*:*",
                        "matchCriteriaId": "51D3BE2B-5A01-4AD4-A436-0056B50A535D",
                    },
                    {
                        "criteria": "cpe:2.3:o:apple:iphone_os:3.1.3:*:*:*:*:*:*:*",
                        "matchCriteriaId": "126EF22D-29BC-4366-97BC-B261311E6251",
                    },
                ],
            },
        }
    )


def test_parse_cpe_matches_returns_softwares_and_relationships(indicator_with_cpes):
    softwares, relationships = cpe_match.parse_cpe_matches(indicator_with_cpes)
    software_cpes = {s.id: s.cpe for s in softwares}
    assert "cpe:2.3:o:apple:iphone_os:3.1.3:*:*:*:*:*:*:*" in software_cpes.values()
    assert (
        "cpe:2.3:o:apple:iphone_os:3.1.3:-:ipodtouch:*:*:*:*:*"
        in software_cpes.values()
    )
    assert (
        "cpe:2.3:o:apple:iphone_os:3.1:-:ipodtouch:*:*:*:*:*" in software_cpes.values()
    )
    software_rels = [
        (s.source_ref, s.target_ref, s.relationship_type, s.description)
        for s in relationships
    ]
    assert software_rels == [
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--e0227c38-e8ad-5ba4-8b0d-7cef5be1609d",
            "relies-on",
            "CVE-2010-1226 relies on cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--e0227c38-e8ad-5ba4-8b0d-7cef5be1609d",
            "exploits",
            "CVE-2010-1226 exploits cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--dca44a12-afa4-56c7-b474-726bc5eeb4dd",
            "relies-on",
            "CVE-2010-1226 relies on cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:ipod_touch:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--dca44a12-afa4-56c7-b474-726bc5eeb4dd",
            "exploits",
            "CVE-2010-1226 exploits cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:ipod_touch:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--7cd8ece8-d1f0-5f55-9d32-6e29a2db43cf",
            "relies-on",
            "CVE-2010-1226 relies on cpe:2.3:o:apple:iphone_os:3.1:-:iphone:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--7cd8ece8-d1f0-5f55-9d32-6e29a2db43cf",
            "exploits",
            "CVE-2010-1226 exploits cpe:2.3:o:apple:iphone_os:3.1:-:iphone:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--cff0ba60-8770-545d-b64c-3b800b7e681c",
            "relies-on",
            "CVE-2010-1226 relies on cpe:2.3:o:apple:iphone_os:3.1:-:ipodtouch:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--cff0ba60-8770-545d-b64c-3b800b7e681c",
            "exploits",
            "CVE-2010-1226 exploits cpe:2.3:o:apple:iphone_os:3.1:-:ipodtouch:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--665a071e-38eb-51b0-b8f4-43c1f6593323",
            "relies-on",
            "CVE-2010-1226 relies on cpe:2.3:o:apple:iphone_os:3.1.3:*:*:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--665a071e-38eb-51b0-b8f4-43c1f6593323",
            "exploits",
            "CVE-2010-1226 exploits cpe:2.3:o:apple:iphone_os:3.1.3:*:*:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--3f671f53-90bb-5b0a-9e32-67e18381d121",
            "relies-on",
            "CVE-2010-1226 relies on cpe:2.3:o:apple:iphone_os:3.1.3:-:iphone:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--3f671f53-90bb-5b0a-9e32-67e18381d121",
            "exploits",
            "CVE-2010-1226 exploits cpe:2.3:o:apple:iphone_os:3.1.3:-:iphone:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--9be14b44-6d9a-593a-8d88-eccd970a247a",
            "relies-on",
            "CVE-2010-1226 relies on cpe:2.3:o:apple:iphone_os:3.1.3:-:ipodtouch:*:*:*:*:*",
        ),
        (
            "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "software--9be14b44-6d9a-593a-8d88-eccd970a247a",
            "exploits",
            "CVE-2010-1226 exploits cpe:2.3:o:apple:iphone_os:3.1.3:-:ipodtouch:*:*:*:*:*",
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
            "external_id": "CVE-2010-1226",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2010-1226",
        } in relationship.external_references


def test_parse_cpe_matches_empty_for_none():
    softwares, relationships = cpe_match.parse_cpe_matches(None)
    assert softwares == []
    assert relationships == []


def test_CpeMatchGetter__get_matches_for_cve():
    criteria_ids = [
        (
            "cpe:2.3:h:apple:iphone:2g:*:*:*:*:*:*:*",
            "B340EF28-D584-4A2B-B0BD-E2E99142C36D",
        ),
        (
            "cpe:2.3:h:apple:iphone:3gs:*:*:*:*:*:*:*",
            "4926A18C-399F-490A-9CCD-F91C3062F278",
        ),
        (
            "cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:*:*:*",
            "51D3BE2B-5A01-4AD4-A436-0056B50A535D",
        ),
        (
            "cpe:2.3:o:apple:iphone_os:3.1.3:*:*:*:*:*:*:*",
            "126EF22D-29BC-4366-97BC-B261311E6251",
        ),
    ]
    cpes = cpe_match.CpeMatchGetter.get_matches_for_cve("CVE-2010-1226", criteria_ids)
    assert cpes == [
        ("B340EF28-D584-4A2B-B0BD-E2E99142C36D", []),
        ("4926A18C-399F-490A-9CCD-F91C3062F278", []),
        (
            "51D3BE2B-5A01-4AD4-A436-0056B50A535D",
            [
                (
                    "cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:*:*:*",
                    "450BFB64-DC3C-4993-8F08-9D0BA6E239B3",
                ),
                (
                    "cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:ipod_touch:*:*",
                    "6F1DBD05-15C9-4107-8AA7-448A87706268",
                ),
                (
                    "cpe:2.3:o:apple:iphone_os:3.1:-:iphone:*:*:*:*:*",
                    "F84D8E27-004B-4570-BEAB-F67FFAD107FD",
                ),
                (
                    "cpe:2.3:o:apple:iphone_os:3.1:-:ipodtouch:*:*:*:*:*",
                    "789F3331-0C4D-4099-AE14-2CDA74ED49B4",
                ),
            ],
        ),
        (
            "126EF22D-29BC-4366-97BC-B261311E6251",
            [
                (
                    "cpe:2.3:o:apple:iphone_os:3.1.3:*:*:*:*:*:*:*",
                    "979F9441-9B23-4013-8DE2-537C23F5FE9B",
                ),
                (
                    "cpe:2.3:o:apple:iphone_os:3.1.3:-:iphone:*:*:*:*:*",
                    "994D5271-433C-4C5E-A3FB-E1CCB2D90C83",
                ),
                (
                    "cpe:2.3:o:apple:iphone_os:3.1.3:-:ipodtouch:*:*:*:*:*",
                    "3B424F3E-6F65-4C11-9FE2-8E9818A1501D",
                ),
            ],
        ),
    ]
