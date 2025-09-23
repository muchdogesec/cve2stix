"""
Representation of CVE object stored in stix2_bundles/
"""

import contextlib
from dataclasses import dataclass, field
from datetime import datetime
import logging
import re
from typing import ClassVar, List
import uuid
from stix2 import Vulnerability, Software, Indicator, Relationship, Grouping, Identity

from cve2stix import cpe_match

from functools import lru_cache
from .config import DEFAULT_CONFIG as config
from stix2 import Identity

from cve2stix.utils import fetch_url
from .config import DEFAULT_CONFIG as config, Config
from stix2extensions._extensions import vulnerability_scoring_ExtensionDefinitionSMO

from cve2stix.indicator import parse_cve_indicator
from stix2.datastore import DataSourceError

from .loggings import logger

def parse_date(date_str: str):
    return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f")


@dataclass
class CVE:
    vulnerability: Vulnerability
    source: Identity
    indicator: "Indicator | None" = None
    # CVE relationship between vulnerability and indicator
    softwares: List[Software] = field(default_factory=list)
    groupings: List[Grouping] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    source_map: ClassVar[dict[str, Identity]]

    @classmethod
    def from_dict(cls, cve_data) -> "CVE":
        cve_data = cve_data.get("cve", cve_data)
        identity = cls.source_map.get(cve_data["sourceIdentifier"])
        vulnerability = cls.parse_cve_vulnerability(cve_data, identity.id)
        cve = CVE(vulnerability=vulnerability, source=identity)
        indicator = parse_cve_indicator(cve_data, vulnerability)
        if indicator:
            cve.indicator = indicator[0]
            cve.relationships.append(indicator[1])
        groupings, softwares, rels = cpe_match.parse_cpe_matches(cve.indicator)
        cve.relationships.extend(rels)
        cve.softwares.extend(softwares)
        cve.groupings.extend(groupings)
        return cve

    @property
    def objects(self):
        objects = (
            [self.vulnerability, self.source]
            + self.relationships
            + self.softwares
            + self.groupings
        )
        if self.indicator:
            objects.append(self.indicator)
        return objects

    @property
    def name(self):
        return self.vulnerability.name

    @classmethod
    def parse_cve_vulnerability(cls, cve, created_by_ref) -> Vulnerability:
        cve_id = cve["id"]
        vulnerability_dict = {
            "id": "vulnerability--{}".format(
                str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))
            ),
            "created_by_ref": created_by_ref,
            "created": parse_date(cve["published"]),
            "modified": parse_date(cve["lastModified"]),
            "name": cve["id"],
            "description": cls.get_vulnerability_description(cve),
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": cve["id"],
                    "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
                }
            ]
            + cls.parse_other_references(cve),
            "x_cvss": cls.parse_cvss_metrics(cve),
            "extensions": {
                vulnerability_scoring_ExtensionDefinitionSMO.id: {
                    "extension_type": "toplevel-property-extension"
                }
            },
            "labels": cls.get_cve_tags(cve),
            "object_marking_refs": [config.TLP_CLEAR_MARKING_DEFINITION_REF]
            + [config.CVE2STIX_MARKING_DEFINITION_REF.get("id")],
        }
        if cve.get("vulnStatus").lower() in ["rejected", "revoked"]:
            vulnerability_dict["revoked"] = True

        vulnerability = Vulnerability(**vulnerability_dict)
        return vulnerability

    @staticmethod
    def get_vulnerability_description(cve):
        for d in cve["descriptions"]:
            if d.get("lang") == "en":
                return d["value"]
        return cve["descriptions"][0]["value"]

    @staticmethod
    def parse_other_references(cve: dict):
        references = []
        for weakness in cve.get("weaknesses", []):
            if weakness.get("description")[0].get("value") != "NVD-CWE-Other":
                references.append(
                    {
                        "source_name": "cwe",
                        "external_id": weakness.get("description")[0].get("value"),
                        "url": f"https://cwe.mitre.org/data/definitions/{weakness.get('description')[0].get('value')}.html",
                    }
                )

        for reference in cve.get("references", []):
            references.append(
                {
                    "source_name": reference.get("source"),
                    "url": reference.get("url"),
                    "description": ",".join(reference.get("tags", [])),
                }
            )
        for key in ["vulnStatus"]:
            references.append(
                {
                    "source_name": key,
                    "description": cve.get(key),
                }
            )
        return references

    @staticmethod
    def parse_cvss_metrics(cve):
        retval = {}
        pattern = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
        try:
            # labels.extend(dict(source_name=f'cvss_metric-{key}', description=metric) for key, metric in cve.get("metrics").items())
            for metrics in cve.get("metrics", {}).values():
                cvss_data = metrics[0]
                cvss_data.update(cvss_data.pop("cvssData", {}))
                version = "v" + cvss_data["version"].lower().replace(".", "_")
                metric = retval[version] = {}
                metric["type"] = cvss_data["type"]
                metric["source"] = cvss_data["source"]
                for cvss_key in [
                    "exploitabilityScore",
                    "impactScore",
                    "vectorString",
                    "baseScore",
                    "baseSeverity",
                ]:
                    if cvss_value := cvss_data.get(cvss_key):
                        cvss_key = pattern.sub("_", cvss_key).lower()
                        metric[cvss_key] = cvss_value
        except Exception as e:
            logging.error(e)
        return retval

    @staticmethod
    def get_cve_tags(cve):
        tags = []
        for tag_item in cve.get("cveTags", []):
            tags.extend(tag_item.get("tags", []))
        return tags


def parse_cve_api_response(cve_content, config: Config) -> List[CVE]:
    parsed_response = []
    CVE.source_map = fetch_source_map()
    for cve_item in cve_content["vulnerabilities"]:
        cve = CVE.from_dict(cve_item)
        logger.info(f"CVE-> {cve.name}")
        for object in cve.objects:
            with contextlib.suppress(DataSourceError):
                config.fs.add(object)
    return parsed_response


def fetch_source_map():
    sources: dict[str, Identity] = {}
    def parse(response, *args):
        for source in response.get("sources", []):
            parsed_source = Identity(
                type="identity",
                spec_version="2.1",
                id="identity--{}".format(
                    str(uuid.uuid5(config.namespace, source["contactEmail"]))
                ),
                created_by_ref=config.CVE2STIX_IDENTITY_REF.get("id"),
                created=parse_date(source["created"]),
                modified=parse_date(source["lastModified"]),
                name=source["name"],
                identity_class="organization",
                contact_information=source["contactEmail"],
                object_marking_refs=[
                    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                    "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
                ],
                external_references=[
                    dict(source_name="sourceIdentifier", external_id=identifier)
                    for identifier in source["sourceIdentifiers"]
                ],
            )
            for identifier in source["sourceIdentifiers"]:
                sources[identifier] = parsed_source

    fetch_url(
        url=config.SOURCE_IDENTIFIERS_URL,
        config=config,
        callback=parse,
    )
    return sources
