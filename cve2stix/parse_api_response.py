from datetime import datetime
import re
import uuid
import sys
import json
import time
import requests
from stix2 import Vulnerability, Indicator, Relationship, Report
from typing import List

from .epss import EPSSManager
from .config import Config
from .helper import cleanup
from .loggings import logger
from .cve import CVE
from .utils import fetch_url, unescape_cpe_string
from stix2extensions._extensions import indicator_vulnerable_cpes_ExtensionDefinitionSMO, vulnerability_scoring_ExtensionDefinitionSMO, report_epss_scoring_ExtensionDefinitionSMO

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
            metric["type"] = cvss_data['type']
            metric["source"] = cvss_data['source']
            for cvss_key in ["exploitabilityScore", "impactScore", "vectorString", "baseScore", "baseSeverity"]:
                if cvss_value := cvss_data.get(cvss_key):
                    cvss_key = pattern.sub('_', cvss_key).lower()
                    metric[cvss_key] = cvss_value
            # break # only record first one
    except Exception as e:
        logger.error(e)
    return retval


def parse_other_references(cve: dict):
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
    for key in ["vulnStatus", "sourceIdentifier"]:
        references.append({
            "source_name": key,
            "description": cve.get(key),
        })
    return references


def build_patterns_for_cve(cve_id: str, pattern_configurations, config: Config):
    patterns = []
    vulnerable_cpe_names = []
    non_vulnerable_cpes = []
    cpe_names_all = []
    JOINER = " OR "

    for pconfig in pattern_configurations:
        pconfig_operator = " {} " .format(pconfig.get("operator", JOINER).strip())
        node_patterns = []
        for node in pconfig.get("nodes"):
            node_operator = " {} " .format(node.get("operator", JOINER).strip())
            node_matches = []
            for match in node.get("cpeMatch", []):
                node_matches.append(f"software:cpe={unescape_cpe_string(match['criteria'])}")
                cpe_match = dict(criteria=match['criteria'], matchCriteriaId=match['matchCriteriaId'])
                if match.get('vulnerable'):
                    vulnerable_cpe_names.append(cpe_match)
                else:
                    non_vulnerable_cpes.append(cpe_match)
            node_patterns.append("[{}]".format(node_operator.join(node_matches)))
            
        patterns.append("({})".format(pconfig_operator.join(node_patterns)))
    return dict(not_vulnerable=non_vulnerable_cpes, vulnerable=vulnerable_cpe_names), JOINER.join(patterns), cpe_names_all


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
        "extensions": {
            vulnerability_scoring_ExtensionDefinitionSMO.id: {
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

def parse_cve_indicator(cve:dict, vulnerability: Vulnerability, config: Config) -> tuple[Indicator, Relationship]:
    if not cve.get("configurations"):
        return []
    cpe_names, pattern_so_far, cpeIds = build_patterns_for_cve(cve["id"], cve.get("configurations", []), config)

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
            indicator_vulnerable_cpes_ExtensionDefinitionSMO.id: {
                "extension_type": "toplevel-property-extension"
            }
        },
        "x_cpes": cpe_names,
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

def parse_cve_epss_report(cve: dict, vulnerability: Vulnerability, config: Config):
    try:
        
        cve_id = cve.get('id')
        epss_data = EPSSManager.get_data_for_cve(cve_id)
        name = f"EPSS Scores: {cve_id}"

        if epss_data:
            epss_data = [epss_data]
        else:
            epss_data = []

        modified = vulnerability['created']
        if epss_data:
            modified = datetime.strptime(epss_data[-1]["date"], "%Y-%m-%d").date()

        return Report(
            created=modified,
            modified=modified,
            published=modified,
            name=name,
            x_epss=epss_data,
            object_refs=[
                vulnerability.id,
            ],
            extensions= {
                report_epss_scoring_ExtensionDefinitionSMO.id: {
                    "extension_type": "toplevel-property-extension"
                }
            },
            object_marking_refs=vulnerability['object_marking_refs'],
            created_by_ref=vulnerability['created_by_ref'],
            external_references=vulnerability['external_references'][:1],

        )
    except:
        return []


def parse_cve_kev(cve: dict, vulnerability: Vulnerability, config: Config):
    if not cve.get("cisaVulnerabilityName"):
        return []
    return Report(            
            type="report",
            spec_version="2.1",
            created_by_ref="identity--562918ee-d5da-5579-b6a1-fae50cc6bad3",
            created=vulnerability.created,
            modified=vulnerability.modified,
            published=vulnerability.created,
            name=f"CISA KEV: {cve['id']}",
            description="Name: {cisaVulnerabilityName}\n\nRequired action: {cisaRequiredAction}\n\nAction due by: {cisaActionDue}".format_map(cve),
            object_refs=[
                vulnerability.id
            ],
            external_references=[
                {
                    "source_name": "cve",
                    "external_id": cve['id'],
                    "url": "https://nvd.nist.gov/vuln/detail/" + cve['id']
                }
            ],
            object_marking_refs=vulnerability.object_marking_refs,
    )
    
    
def parse_cve_api_response(
    cve_content, config: Config) -> List[CVE]:
    parsed_response = []
    for cve_item in cve_content["vulnerabilities"]:
        cve = cve_item["cve"]
        logger.info(f"CVE-> {cve.get('id')}")
        vulnerability = parse_cve_vulnerability(cve, config)
        config.fs.add(vulnerability)
        config.fs.add(parse_cve_indicator(cve, vulnerability, config))
        config.fs.add(parse_cve_kev(cve, vulnerability, config))
        config.fs.add(parse_cve_epss_report(cve, vulnerability, config))
    return parsed_response
