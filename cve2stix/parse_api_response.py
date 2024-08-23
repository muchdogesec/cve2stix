from datetime import datetime
import re
import uuid
import sys
import json
import time
import requests
from stix2 import Vulnerability, Indicator, Relationship, Sighting
from typing import List, Never
from .config import Config
from .helper import cleanup
from .loggings import logger
from .cve import CVE
from .utils import fetch_url, unescape_cpe_string


sys.setrecursionlimit(10000)

def retrieve_epss_metrics(epss_url, cve_id):
    try:
       query = f"{epss_url}?cve={cve_id}"
       response = requests.get(query)
       #logger.info(f"Status Code => {response.status_code}")
       if response.status_code != 200:
           logger.warning("Got response status code %d.", response.status_code)
           raise requests.ConnectionError

    except requests.ConnectionError as ex:
       logger.error(ex)
       raise

    data = response.json()
    extensions = {}
    if epss_data := data.get('data'):
        for key, source_name in [('epss', 'score'), ('percentile', 'percentile'), ('date', 'date')]:
            extensions[source_name] = epss_data[0].get(key)
    return extensions


def parse_cvss_metrics(cve):
    retval = {}
    pattern = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
    try:
        # labels.extend(dict(source_name=f'cvss_metric-{key}', description=metric) for key, metric in cve.get("metrics").items())
        for metrics in cve.get('metrics', {}).values():
            cvss_data = metrics[0]
            cvss_data.update(cvss_data.pop('cvssData', {}))
            version = "v"+cvss_data['version'].lower().replace('.', "_")
            metric = retval[version] = {}
            for cvss_key in ["exploitabilityScore", "impactScore", "vectorString", "baseScore", "baseSeverity"]:
                if cvss_value := cvss_data.get(cvss_key):
                    cvss_key = pattern.sub('_', cvss_key).lower()
                    metric[cvss_key] = cvss_value
            # break # only record first one
    except Exception as e:
        logger.error(e)
    return retval


def parse_other_references(cve):
    references = []
    for weakness in cve.get("weaknesses", []):
        if weakness.get("description")[0].get("value")!="NVD-CWE-Other":
            references.append({
                "source_name": "cwe",
                "external_id": weakness.get("description")[0].get("value"),
                "url": f"https://cwe.mitre.org/data/definitions/{weakness.get('description')[0].get('value')}.html"
            })

    for reference in cve.get("references", []):
        references.append({
            "source_name": reference.get("source"),
            "url": reference.get("url"),
            "description": ",".join(reference.get("tags", []))
        })
    return references


def build_patterns_for_cve(cve_id: str, pattern_configurations, config: Config):
    patterns = []
    vulnerable_cpe_names = []
    cpe_names_all = []
    cpe_name_ids = []
    criteria_id_map : dict[str, list] = {}
    JOINER = " OR "
    def parse_into(response: dict, config):
        for match_data in response.get("matchStrings", []):
            match_data = match_data["matchString"]
            match_strings = []
            cpe_names = []
            for cpe in match_data.get("matches", []):
                cpe_name = cpe["cpeName"]
                cpe_names.append(cpe_name)
                match_strings.append(f"software:cpe='{unescape_cpe_string(cpe_name)}'")
                cpe_name_ids.append(cpe["cpeNameId"])
            if not match_strings:
                cpe_name = match_data['criteria']
                match_strings.append(f"software:cpe='{unescape_cpe_string(cpe_name)}'")
                cpe_names = [cpe_name]
            criteria_id_map[match_data["matchCriteriaId"]] = "(" + JOINER.join(match_strings) + ")", cpe_names
            cpe_names_all.extend(cpe_names)
    fetch_url(config.cpematch_api_endpoint+cve_id, config, parse_into)

    for pconfig in pattern_configurations:
        pconfig_operator = " {} " .format(pconfig.get("operator", JOINER).strip())
        node_patterns = []
        for node in pconfig.get("nodes"):
            node_operator = " {} " .format(node.get("operator", JOINER).strip())
            node_matches = []
            for match in node.get("cpeMatch", []):
                pattern, cpe_names = criteria_id_map[match['matchCriteriaId']]
                node_matches.append(pattern)
                if match.get('vulnerable'):
                    vulnerable_cpe_names.extend(cpe_names)
            node_patterns.append("[{}]".format(node_operator.join(node_matches)))
            
        patterns.append("({})".format(pconfig_operator.join(node_patterns)))
    return vulnerable_cpe_names, JOINER.join(patterns), cpe_names_all


def get_description(cve):
    for d in cve["descriptions"]:
        if d.get('lang') == 'en':
            return d["value"]
    return cve["descriptions"][0]["value"]

def get_cve_tags(cve):
    tags = []
    for tag_item in cve.get('cveTags', []):
        tags.extend(tag_item.get('tags', []))
    return tags


def parse_cve_vulnerability(cve, config: Config) -> Vulnerability:
    cve_id = cve["id"]
    vulnerability_dict = {
        "id": "vulnerability--{}".format(
            str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))
        ),
        "created_by_ref": config.CVE2STIX_IDENTITY_REF.get("id"),
        "created": datetime.strptime(cve["published"], "%Y-%m-%dT%H:%M:%S.%f"),
        "modified": datetime.strptime(cve["lastModified"], "%Y-%m-%dT%H:%M:%S.%f"),
        "name": cve["id"],
        "description": get_description(cve),
        "external_references": cleanup(
            [
                {
                    "source_name": "cve",
                    "external_id": cve["id"],
                    "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
                }
            ]
            + parse_other_references(cve)
        ),
        "x_cvss": parse_cvss_metrics(cve),
        "x_epss": retrieve_epss_metrics(config.epss_endpoint, cve_id),
        "extensions": {
            "extension-definition--2c5c13af-ee92-5246-9ba7-0b958f8cd34a": {
                "extension_type": "toplevel-property-extension"
            }
        },
        "labels": get_cve_tags(cve),
        "object_marking_refs": [config.TLP_CLEAR_MARKING_DEFINITION_REF]
        + [config.CVE2STIX_MARKING_DEFINITION_REF.get("id")],
    }
    if cve.get("vulnStatus").lower() in ["rejected", "revoked"]:
        vulnerability_dict['revoked'] = True

    vulnerability = Vulnerability(**vulnerability_dict)
    return vulnerability

def parse_cve_indicator(cve:dict, vulnerability: Vulnerability, config: Config) -> tuple[Indicator, Relationship]|list[Never]:
    if not cve.get("configurations"):
        return []
    vulnerable_cpe_names, pattern_so_far, cpeIds = build_patterns_for_cve(cve["id"], cve.get("configurations", []), config)

    indicator_dict = {
        "id": "indicator--{}".format(str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))),
        "created_by_ref": config.CVE2STIX_IDENTITY_REF.get("id"),
        "created": vulnerability.created,
        "modified": vulnerability.modified,
        "indicator_types": ["compromised"],
        "name": cve["id"],
        "description": vulnerability.description,
        "pattern_type": "stix",
        "pattern": pattern_so_far,
        "valid_from": vulnerability.created,
        "object_marking_refs": [config.TLP_CLEAR_MARKING_DEFINITION_REF]+[config.CVE2STIX_MARKING_DEFINITION_REF.get("id")],
        "extensions":{
            "extension-definition--ad995824-2901-5f6e-890b-561130a239d4": {
                "extension_type": "toplevel-property-extension"
            }
        },
        "x_vulnerable_cpes": vulnerable_cpe_names,
        "external_references": cleanup([
            {
                "source_name": "cve",
                "external_id": cve["id"],
                "url": "https://nvd.nist.gov/vuln/detail/" + cve["id"],
            },

        ])
    }
    
    indicator = Indicator(**indicator_dict)
    relationship = Relationship(
        id="relationship--{}".format(str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))),
        created=vulnerability["created"],
        created_by_ref=config.CVE2STIX_IDENTITY_REF.get("id"),
        modified=vulnerability["modified"],
        description=f"The Indicator contains a pattern that detects {indicator.name}",
        relationship_type="detects",
        source_ref=indicator,
        target_ref=vulnerability,
        object_marking_refs=[config.TLP_CLEAR_MARKING_DEFINITION_REF] + [config.CVE2STIX_MARKING_DEFINITION_REF.get("id")],
        external_references= [
            {
                "source_name": "cve",
                "external_id": cve.get("id"),
                "url": "https://nvd.nist.gov/vuln/detail/{}".format(cve.get('id'))
            }
        ]
    )
    return [indicator, relationship]

def parse_cve_sighting(cve: dict, vulnerability: Vulnerability, config: Config):
    if cve.get("cisaVulnerabilityName"):
        return Sighting(
            id="sighting--{}".format(
                str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))
            ),
            sighting_of_ref=vulnerability.id,
            created_by_ref=config.CVE2STIX_IDENTITY_REF.get("id"),
            created=vulnerability.created,
            modified=vulnerability.modified,
            description="CISA KEV: {cisaVulnerabilityName}\n\n {cisaRequiredAction}\n\n Action due by: {cisaActionDue}".format_map(cve),
            object_marking_refs=vulnerability.object_marking_refs,
            external_references=[
                {
                    "source_name": "cve",
                    "external_id": cve.get("id"),
                    "url": "https://nvd.nist.gov/vuln/detail/{}".format(cve.get("id")),
                }
            ],
        )
    return []
def parse_cve_api_response(
    cve_content, config: Config) -> List[CVE]:
    parsed_response = []
    for cve_item in cve_content["vulnerabilities"]:
        cve = cve_item["cve"]
        logger.info(f"CVE-> {cve.get('id')}")
        vulnerability = parse_cve_vulnerability(cve, config)
        config.fs.add(vulnerability)
        config.fs.add(parse_cve_indicator(cve, vulnerability, config))
        config.fs.add(parse_cve_sighting(cve, vulnerability, config))
    return parsed_response
