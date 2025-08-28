"""
Representation of CVE object stored in stix2_bundles/
"""

import contextlib
from dataclasses import dataclass, field
from datetime import datetime
import logging
import re
from typing import List
import uuid
from stix2 import Vulnerability, Software, Indicator, Relationship, Grouping

from cve2stix import cpe_match
from .config import DEFAULT_CONFIG as config, Config
from stix2extensions._extensions import vulnerability_scoring_ExtensionDefinitionSMO

from cve2stix.indicator import parse_cve_indicator
from stix2.datastore import DataSourceError

from .loggings import logger


@dataclass
class CVE:
    vulnerability: Vulnerability
    indicator: "Indicator | None" = None
    # CVE relationship between vulnerability and indicator
    softwares: List[Software] = field(default_factory=list)
    groupings: List[Grouping] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data) -> "CVE":
        data = data.get("cve", data)
        vulnerability = cls.parse_cve_vulnerability(data)
        cve = CVE(vulnerability=vulnerability)
        indicator = parse_cve_indicator(data, vulnerability)
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
        objects = [self.vulnerability] + self.relationships + self.softwares + self.groupings
        if self.indicator:
            objects.append(self.indicator)
        return objects

    @property
    def name(self):
        return self.vulnerability.name

    @classmethod
    def parse_cve_vulnerability(cls, cve) -> Vulnerability:
        cve_id = cve["id"]
        vulnerability_dict = {
            "id": "vulnerability--{}".format(
                str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))
            ),
            "created_by_ref": config.CVE2STIX_IDENTITY_REF.get("id"),
            "created": datetime.strptime(cve["published"], "%Y-%m-%dT%H:%M:%S.%f"),
            "modified": datetime.strptime(cve["lastModified"], "%Y-%m-%dT%H:%M:%S.%f"),
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
        for key in ["vulnStatus", "sourceIdentifier"]:
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
    for cve_item in cve_content["vulnerabilities"]:
        cve = CVE.from_dict(cve_item)
        logger.info(f"CVE-> {cve.name}")
        for object in cve.objects:
            with contextlib.suppress(DataSourceError):
                config.fs.add(object)
    return parsed_response
