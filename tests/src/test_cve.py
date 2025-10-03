import json
from unittest.mock import call, patch
import pytest
from datetime import datetime, timezone
from cve2stix import cve as cve_module
from stix2 import parse as parse_stix


@pytest.fixture
def example_cve(example_cve_response):
    return example_cve_response["vulnerabilities"][1]


@pytest.fixture
def example_cve_response():
    return {
        "resultsPerPage": 2,
        "startIndex": 0,
        "totalResults": 2,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2025-08-25T14:23:23.134",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-1999-1392",
                    "sourceIdentifier": "cve@mitre.org",
                    "published": "1990-10-03T04:00:00.000",
                    "lastModified": "2025-04-03T01:03:51.193",
                    "vulnStatus": "Deferred",
                    "cveTags": [],
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Vulnerability in restore0.9 installation script in NeXT 1.0a and 1.0 allows local users to gain root privileges.",
                        },
                        {
                            "lang": "es",
                            "value": "Vulnerabilidad en el script de instalación restore0.9  en  NeXT 1.0a y 1.0 permite a usuarios locales conseguir privilegios de root.",
                        },
                    ],
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "2.0",
                                    "vectorString": "AV:L\\/AC:L\\/Au:N\\/C:C\\/I:C\\/A:C",
                                    "baseScore": 7.2,
                                    "accessVector": "LOCAL",
                                    "accessComplexity": "LOW",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "COMPLETE",
                                    "integrityImpact": "COMPLETE",
                                    "availabilityImpact": "COMPLETE",
                                },
                                "baseSeverity": "HIGH",
                                "exploitabilityScore": 3.9,
                                "impactScore": 10.0,
                                "acInsufInfo": False,
                                "obtainAllPrivilege": True,
                                "obtainUserPrivilege": False,
                                "obtainOtherPrivilege": False,
                                "userInteractionRequired": False,
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "NVD-CWE-Other"}],
                        }
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "negate": False,
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:next:nex:1.0a:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "B477FD08-1821-4825-845F-954665A264AC",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:next:next:1.0:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "EB8A63B4-195D-4AF0-8FE9-EB882BFF098E",
                                        },
                                    ],
                                }
                            ]
                        }
                    ],
                    "references": [
                        {
                            "url": "http:\\/\\/ciac.llnl.gov\\/ciac\\/bulletins\\/b-01.shtml",
                            "source": "cve@mitre.org",
                            "tags": ["Patch", "Vendor Advisory"],
                        },
                        {
                            "url": "http:\\/\\/www.cert.org\\/advisories\\/CA-1990-06.html",
                            "source": "cve@mitre.org",
                            "tags": [
                                "Patch",
                                "Third Party Advisory",
                                "US Government Resource",
                            ],
                        },
                        {
                            "url": "http:\\/\\/www.iss.net\\/security_center\\/static\\/7144.php",
                            "source": "cve@mitre.org",
                        },
                        {
                            "url": "http:\\/\\/www.securityfocus.com\\/bid\\/9",
                            "source": "cve@mitre.org",
                            "tags": ["Patch", "Vendor Advisory"],
                        },
                        {
                            "url": "http:\\/\\/ciac.llnl.gov\\/ciac\\/bulletins\\/b-01.shtml",
                            "source": "af854a3a-2127-422b-91ae-364da2661108",
                            "tags": ["Patch", "Vendor Advisory"],
                        },
                        {
                            "url": "http:\\/\\/www.cert.org\\/advisories\\/CA-1990-06.html",
                            "source": "af854a3a-2127-422b-91ae-364da2661108",
                            "tags": [
                                "Patch",
                                "Third Party Advisory",
                                "US Government Resource",
                            ],
                        },
                        {
                            "url": "http:\\/\\/www.iss.net\\/security_center\\/static\\/7144.php",
                            "source": "af854a3a-2127-422b-91ae-364da2661108",
                        },
                        {
                            "url": "http:\\/\\/www.securityfocus.com\\/bid\\/9",
                            "source": "af854a3a-2127-422b-91ae-364da2661108",
                            "tags": ["Patch", "Vendor Advisory"],
                        },
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-0278",
                    "sourceIdentifier": "cna@vuldb.com",
                    "published": "2024-01-07T14:15:43.297",
                    "lastModified": "2024-11-21T08:46:12.893",
                    "vulnStatus": "Modified",
                    "cveTags": [],
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "A vulnerability, which was classified as critical, has been found in Kashipara Food Management System up to 1.0. This issue affects some unknown processing of the file partylist_edit_submit.php. The manipulation of the argument id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-249833 was assigned to this vulnerability.",
                        },
                        {
                            "lang": "es",
                            "value": "Una vulnerabilidad fue encontrada en Kashipara Food Management System hasta 1.0 y clasificada como cr\u00edtica. Este problema afecta un procesamiento desconocido del archivo partylist_edit_submit.php. La manipulaci\u00f3n del argumento id conduce a la inyecci\u00f3n de SQL. El ataque puede iniciarse de forma remota. La explotaci\u00f3n ha sido divulgada al p\u00fablico y puede utilizarse. A esta vulnerabilidad se le asign\u00f3 el identificador VDB-249833.",
                        },
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "cna@vuldb.com",
                                "type": "Secondary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                                    "baseScore": 6.3,
                                    "baseSeverity": "MEDIUM",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "LOW",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "LOW",
                                    "integrityImpact": "LOW",
                                    "availabilityImpact": "LOW",
                                },
                                "exploitabilityScore": 2.8,
                                "impactScore": 3.4,
                            },
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                                    "baseScore": 6.5,
                                    "baseSeverity": "MEDIUM",
                                    "attackVector": "NETWORK",
                                    "attackComplexity": "LOW",
                                    "privilegesRequired": "LOW",
                                    "userInteraction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "NONE",
                                    "availabilityImpact": "NONE",
                                },
                                "exploitabilityScore": 2.8,
                                "impactScore": 3.6,
                            },
                        ],
                        "cvssMetricV2": [
                            {
                                "source": "cna@vuldb.com",
                                "type": "Secondary",
                                "cvssData": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
                                    "baseScore": 6.5,
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "LOW",
                                    "authentication": "SINGLE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "PARTIAL",
                                    "availabilityImpact": "PARTIAL",
                                },
                                "baseSeverity": "MEDIUM",
                                "exploitabilityScore": 8.0,
                                "impactScore": 6.4,
                                "acInsufInfo": False,
                                "obtainAllPrivilege": False,
                                "obtainUserPrivilege": False,
                                "obtainOtherPrivilege": False,
                                "userInteractionRequired": False,
                            }
                        ],
                    },
                    "weaknesses": [
                        {
                            "source": "cna@vuldb.com",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "CWE-89"}],
                        }
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "negate": False,
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:kashipara:food_management_system:*:*:*:*:*:*:*:*",
                                            "versionEndIncluding": "1.0",
                                            "matchCriteriaId": "BBBECC06-F3D5-4B63-8EB2-8E44A64624C5",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                    "references": [
                        {
                            "url": "https://github.com/E1CHO/cve_hub/blob/main/Food%20Management%20System/Food%20Management%20System%20-%20vuln%2010.pdf",
                            "source": "cna@vuldb.com",
                            "tags": ["Exploit", "Third Party Advisory"],
                        },
                        {
                            "url": "https://vuldb.com/?ctiid.249833",
                            "source": "cna@vuldb.com",
                            "tags": ["Permissions Required", "Third Party Advisory"],
                        },
                        {
                            "url": "https://vuldb.com/?id.249833",
                            "source": "cna@vuldb.com",
                            "tags": ["Third Party Advisory"],
                        },
                        {
                            "url": "https://github.com/E1CHO/cve_hub/blob/main/Food%20Management%20System/Food%20Management%20System%20-%20vuln%2010.pdf",
                            "source": "af854a3a-2127-422b-91ae-364da2661108",
                            "tags": ["Exploit", "Third Party Advisory"],
                        },
                        {
                            "url": "https://vuldb.com/?ctiid.249833",
                            "source": "af854a3a-2127-422b-91ae-364da2661108",
                            "tags": ["Permissions Required", "Third Party Advisory"],
                        },
                        {
                            "url": "https://vuldb.com/?id.249833",
                            "source": "af854a3a-2127-422b-91ae-364da2661108",
                            "tags": ["Third Party Advisory"],
                        },
                    ],
                }
            },
        ],
    }


def test_from_dict_creates_cve(example_cve, source_identity):
    with patch("cve2stix.cpe_match.parse_cpe_matches") as mock_parse_softwares:
        mock_parse_softwares.return_value = (
            [dict(group=1)],
            [dict(software_a=1), dict(b=2)],
            [
                dict(c=3),
                dict(b=2),
            ],
        )
        cve_module.CVE.source_map = {"cna@vuldb.com": parse_stix(source_identity)}
        cve_obj = cve_module.CVE.from_dict(example_cve)
        assert isinstance(cve_obj, cve_module.CVE)
        assert isinstance(cve_obj.vulnerability, cve_module.Vulnerability)
        assert cve_obj.vulnerability.name == "CVE-2024-0278"
        assert cve_obj.indicator is None or isinstance(
            cve_obj.indicator, cve_module.Indicator
        )
        assert cve_obj.groupings == mock_parse_softwares.return_value[0]
        assert cve_obj.softwares == mock_parse_softwares.return_value[1]
        for rel in mock_parse_softwares.return_value[2]:
            assert rel in cve_obj.relationships


def test_cve_objects(source_identity):
    cve_obj = cve_module.CVE(
        cve_module.Vulnerability(name="vuln"), source=source_identity
    )
    cve_obj.softwares.extend([dict(a=1), dict(b=2)])
    cve_obj.relationships.extend([dict(c=3), dict(b=2)])
    assert cve_obj.objects == [
        cve_obj.vulnerability,
        source_identity,
        *cve_obj.relationships,
        *cve_obj.softwares,
    ]
    cve_obj.indicator = dict(e=9)
    assert cve_obj.objects == [
        cve_obj.vulnerability,
        source_identity,
        *cve_obj.relationships,
        *cve_obj.softwares,
        *cve_obj.groupings,
        cve_obj.indicator,
    ]


def test_parse_cve_vulnerability_builds_correct_vuln(example_cve, source_identity):
    vuln = cve_module.CVE.parse_cve_vulnerability(
        example_cve["cve"], source_identity["id"]
    )
    assert json.loads(vuln.serialize()) == {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": "vulnerability--46ef129c-a626-57ab-b55c-61c8e52e3cb5",
        "created_by_ref": "identity--a9546a6d-7e78-5367-847d-8d10e8a77bc9",
        "created": "2024-01-07T14:15:43.297Z",
        "modified": "2024-11-21T08:46:12.893Z",
        "name": "CVE-2024-0278",
        "description": "A vulnerability, which was classified as critical, has been found in Kashipara Food Management System up to 1.0. This issue affects some unknown processing of the file partylist_edit_submit.php. The manipulation of the argument id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-249833 was assigned to this vulnerability.",
        "external_references": [
            {
                "source_name": "cve",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0278",
                "external_id": "CVE-2024-0278",
            },
            {
                "source_name": "cwe",
                "url": "https://cwe.mitre.org/data/definitions/CWE-89.html",
                "external_id": "CWE-89",
            },
            {
                "source_name": "cna@vuldb.com",
                "description": "Exploit,Third Party Advisory",
                "url": "https://github.com/E1CHO/cve_hub/blob/main/Food%20Management%20System/Food%20Management%20System%20-%20vuln%2010.pdf",
            },
            {
                "source_name": "cna@vuldb.com",
                "description": "Permissions Required,Third Party Advisory",
                "url": "https://vuldb.com/?ctiid.249833",
            },
            {
                "source_name": "cna@vuldb.com",
                "description": "Third Party Advisory",
                "url": "https://vuldb.com/?id.249833",
            },
            {
                "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                "description": "Exploit,Third Party Advisory",
                "url": "https://github.com/E1CHO/cve_hub/blob/main/Food%20Management%20System/Food%20Management%20System%20-%20vuln%2010.pdf",
            },
            {
                "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                "description": "Permissions Required,Third Party Advisory",
                "url": "https://vuldb.com/?ctiid.249833",
            },
            {
                "source_name": "af854a3a-2127-422b-91ae-364da2661108",
                "description": "Third Party Advisory",
                "url": "https://vuldb.com/?id.249833",
            },
            {"source_name": "vulnStatus", "description": "Modified"},
        ],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
        ],
        "extensions": {
            "extension-definition--2c5c13af-ee92-5246-9ba7-0b958f8cd34a": {
                "extension_type": "toplevel-property-extension"
            }
        },
        "x_cvss": {
            "v3_1": {
                "type": "Secondary",
                "source": "cna@vuldb.com",
                "exploitability_score": 2.8,
                "impact_score": 3.4,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                "base_score": 6.3,
                "base_severity": "MEDIUM",
            },
            "v2_0": {
                "type": "Secondary",
                "source": "cna@vuldb.com",
                "exploitability_score": 8.0,
                "impact_score": 6.4,
                "vector_string": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
                "base_score": 6.5,
                "base_severity": "MEDIUM",
            },
        },
    }


def test_parse_other_references_includes_cwe_and_references(example_cve):
    refs = cve_module.CVE.parse_other_references(example_cve["cve"])
    cwe_refs = [r for r in refs if r["source_name"] == "cwe"]
    assert any("CWE-89" in r["external_id"] for r in cwe_refs)
    other_refs = [r for r in refs if r["source_name"] == "cna@vuldb.com"]
    assert any("vuldb" in r["url"] for r in other_refs)


def test_parse_cvss_metrics_returns_both_v3_and_v2(example_cve):
    metrics = cve_module.CVE.parse_cvss_metrics(example_cve["cve"])
    assert metrics["v3_1"] == {
        "type": "Secondary",
        "source": "cna@vuldb.com",
        "exploitability_score": 2.8,
        "impact_score": 3.4,
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
        "base_score": 6.3,
        "base_severity": "MEDIUM",
    }
    assert metrics["v2_0"] == {
        "type": "Secondary",
        "source": "cna@vuldb.com",
        "exploitability_score": 8.0,
        "impact_score": 6.4,
        "vector_string": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
        "base_score": 6.5,
        "base_severity": "MEDIUM",
    }


def test_get_cve_tags_empty_list_for_empty_tags(example_cve):
    tags = cve_module.CVE.get_cve_tags(example_cve["cve"])
    assert tags == []


def test_parse_cve_api_response_parses_all():
    resp = {"vulnerabilities": [1, 2]}
    with (
        patch("cve2stix.cve.CVE.from_dict") as mock_cve,
        patch("stix2.FileSystemStore.add") as mock_fs_add,
    ):
        mock_cve.return_value.objects = [3, 4, 5]
        cve_module.parse_cve_api_response(resp, cve_module.config)
        assert isinstance(
            cve_module.CVE.source_map, dict
        ), f"bad source_map: {cve_module.CVE.source_map}"
        mock_cve.assert_has_calls([call(1), call(2)], any_order=True)
        mock_fs_add.assert_has_calls([call(3), call(4), call(5)], any_order=True)


def test_parse_cve_api_response(example_cve_response):
    objects = []
    with patch("stix2.FileSystemStore.add", side_effect=objects.append) as mock_fs_add:
        cve_module.parse_cve_api_response(example_cve_response, cve_module.config)
        mock_fs_add.assert_called()

    assert isinstance(
        cve_module.CVE.source_map, dict
    ), f"bad source_map: {cve_module.CVE.source_map}"
    assert {obj["id"] for obj in objects} == {
        "vulnerability--46ef129c-a626-57ab-b55c-61c8e52e3cb5",
        "vulnerability--a6fd09c6-7a26-5ccb-9e4a-bd6b724df85b",
        "relationship--9607faa4-6818-53a0-9e17-b4e0f3773e7f",
        "relationship--46ef129c-a626-57ab-b55c-61c8e52e3cb5",
        "indicator--a6fd09c6-7a26-5ccb-9e4a-bd6b724df85b",
        "relationship--d3c148a4-8382-54cd-bb63-9c4e2cc8a248",
        "grouping--8eade122-52a7-50d9-9626-aaa520f1469b",
        "relationship--5cc289f4-0e0a-5753-8a35-bf79f2bededc",
        "grouping--8d9f263a-29d7-5456-8fbf-d5f5872f0097",
        "relationship--a6fd09c6-7a26-5ccb-9e4a-bd6b724df85b",
        "indicator--46ef129c-a626-57ab-b55c-61c8e52e3cb5",
        "software--3114e670-1bc4-5bc1-8458-9f302d1891e2",
        "grouping--9a60b644-bd0f-5bd1-b352-cae9187f6d06",
        "identity--a9546a6d-7e78-5367-847d-8d10e8a77bc9",
        "identity--64dfee48-e209-5e25-bad4-dcc80d221a85",
    }


@pytest.fixture
def source_identity():
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--a9546a6d-7e78-5367-847d-8d10e8a77bc9",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2022-03-28T18:15:08.113Z",
        "modified": "2022-03-28T18:15:08.113Z",
        "name": "VulDB",
        "identity_class": "organization",
        "contact_information": "cna@vuldb.com",
        "external_references": [
            {"source_name": "sourceIdentifier", "external_id": "cna@vuldb.com"},
            {
                "source_name": "sourceIdentifier",
                "external_id": "1af790b2-7ee1-4545-860a-a788eba489b5",
            },
        ],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
        ],
    }


def test_fetch_source_map(source_identity):
    source_map = cve_module.fetch_source_map()
    source1 = json.loads(source_map["cna@vuldb.com"].serialize())
    assert source1 == source_identity
