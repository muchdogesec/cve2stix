from datetime import datetime
import itertools
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


def test_get_matches_for_cve_id():
    criteria_matches = cpe_match.get_matches_for_cve("CVE-2010-1226")
    assert {c["matchCriteriaId"] for c in criteria_matches}.issuperset(
        [
            "B340EF28-D584-4A2B-B0BD-E2E99142C36D",
            "4926A18C-399F-490A-9CCD-F91C3062F278",
            "126EF22D-29BC-4366-97BC-B261311E6251",
            "51D3BE2B-5A01-4AD4-A436-0056B50A535D",
        ]
    )


def test_parse_cpe_matches(indicator_with_cpes):
    groupings, softwares, relationships = cpe_match.parse_cpe_matches(
        indicator_with_cpes
    )
    assert {grouping["name"] for grouping in groupings} == {
        "cpe:2.3:o:apple:iphone_os:3.1.3:*:*:*:*:*:*:*",
        "cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:*:*:*",
        "cpe:2.3:h:apple:iphone:3gs:*:*:*:*:*:*:*",
        "cpe:2.3:h:apple:iphone:2g:*:*:*:*:*:*:*",
    }
    assert set(
        itertools.chain(*(grouping["object_refs"] for grouping in groupings))
    ) == {
        software["id"] for software in softwares
    }, "all software must appear in group.object_refs"
    assert (
        len(relationships) == 6
    ), "4 groups (2 vulnerable) (4 in pattern relationships) and 2 vulnerable relationships expected"
    print({r["id"] for r in relationships})


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
