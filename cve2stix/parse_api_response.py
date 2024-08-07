from datetime import datetime
import uuid
import sys
import json
import time
import requests
from stix2 import Vulnerability, Indicator, Relationship, Report
from typing import List
from .config import Config
from .helper import cleanup
from .loggings import logger
from .cve import CVE
from .utils import fetch_url


sys.setrecursionlimit(10000)

#def get_epss_refs(epss, cve):
#    try:
#        query = f"{epss}{cve}"
#        response = requests.get(query)
#        #logger.info(f"Status Code => {response.status_code}")
#        if response.status_code != 200:
#            logger.warning("Got response status code %d.", response.status_code)
#            raise requests.ConnectionError
#
#
#
#   except requests.ConnectionError as ex:
#        logger.error(ex)
#        raise
#
#    data = response.json()
#    extensions = []
#    if epss_data := data.get('data'):
#        for key, source_name in [('epss', 'epssScore'), ('percentile', 'epssPercentile'), ('date', 'epssDate')]:
#            extension = {
#                "source_name": source_name,
#                "url": f"https://api.first.org/data/v1/epss?cve={cve}",
#                "description": epss_data[0].get(key)
#            }
#            extensions.append(extension)
#
#    return extensions


def parse_cvss_metrics_refs(cve):
    labels = []
    cve_id = cve.get('id')
    try:
        key = list(cve.get("metrics").keys())[0]
        container = cve.get("metrics", {}).get(key)[0]
        labels.append(dict(source_name=f"{key}-exploitabilityScore", description=container.get('exploitabilityScore'), url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"))
        labels.append(dict(source_name=f"{key}-impactScore", description=container.get('impactScore'), url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"))
        cvss_data = container.get('cvssData', {})
        for cvss_key in ["vectorString", "baseScore", "baseSeverity"]:
            if cvss_value := cvss_data.get(cvss_key):
                labels.append(dict(source_name=f"{key}-{cvss_key}", description=cvss_value, url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"))

    except Exception as e:
        logger.error(e)
        return labels
    return labels


def external_reference(cve):
    references = []
    for weakness in cve.get("weaknesses", []):
        if weakness.get("description")[0].get("value")!="NVD-CWE-Other":
            references.append({
                "source_name": "cwe",
                "external_id": weakness.get("description")[0].get("value"),
                "url": f"https://cwe.mitre.org/data/definitions/{weakness.get('description')[0].get('value')}.html"
            })

    for reference in cve.get("references"):
        references.append({
            "source_name": reference.get("source"),
            "url": reference.get("url"),
            "description": ",".join(reference.get("tags", []))
        })
    return references



def build_patterns_for_cve(cve_id: str, pattern_configurations, config: Config):
    patterns = []
    cpe_names_all = []
    cpe_name_ids = []
    criteria_id_map : dict[str, list] = {}
    JOINER = " OR "
    def parse_into(response: dict, config):
        for match_data in response.get("matchStrings", []):
            match_data = match_data["matchString"]
            match_strings = []                
            for cpe in match_data.get("matches", []):
                cpe_name = cpe["cpeName"]
                cpe_names_all.append(cpe_name)
                match_strings.append(f"software:cpe='{cpe_name}'")
                cpe_name_ids.append(cpe["cpeNameId"])
            if not match_strings:
                match_strings.append(f"software:cpe='{match_data['criteria']}'")
            criteria_id_map[match_data["matchCriteriaId"]] = "(" + JOINER.join(match_strings) + ")"
    fetch_url(config.cpematch_api_endpoint+cve_id, config, parse_into)

    for pconfig in pattern_configurations:
        pconfig_operator = " {} " .format(pconfig.get("operator", JOINER).strip())
        node_patterns = []
        for node in pconfig.get("nodes"):
            node_operator = " {} " .format(node.get("operator", JOINER).strip())
            node_matches = [criteria_id_map[match["matchCriteriaId"]] for match in node.get("cpeMatch")]
            node_patterns.append("[{}]".format(node_operator.join(node_matches)))
        patterns.append("({})".format(pconfig_operator.join(node_patterns)))
    return JOINER.join(patterns), cpe_name_ids



def parse_cve_api_response(
    cve_content, config: Config) -> List[CVE]:
    parsed_response = []
    for cve_item in cve_content["vulnerabilities"]:
        cve = cve_item["cve"]
        logger.info(f"CVE-> {cve.get('id')}")

        try:
            vulnerability_dict = {
                "id":"vulnerability--{}".format(str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))),
                "created_by_ref": config.CVE2STIX_IDENTITY_REF.get("id"),
                "created": datetime.strptime(cve["published"], "%Y-%m-%dT%H:%M:%S.%f"),
                "modified": datetime.strptime(
                    cve["lastModified"], "%Y-%m-%dT%H:%M:%S.%f"
                ),
                "name": cve["id"],
                "description": cve["descriptions"][0]["value"],
                "external_references": cleanup([
                    {
                        "source_name": "cve",
                        "external_id": cve["id"],
                        "url": "https://nvd.nist.gov/vuln/detail/"+cve["id"],
                    }
                ] + external_reference(cve) + parse_cvss_metrics_refs(cve)),
                # + get_epss_refs(config.epss, cve.get('id')))
                "object_marking_refs": [config.TLP_CLEAR_MARKING_DEFINITION_REF]+[config.CVE2STIX_MARKING_DEFINITION_REF.get("id")],
            }
            if cve.get("vulnStatus").lower() in ["rejected", "revoked"]:
                vulnerability_dict['revoked'] = True


            indicator_dict = None
            if cve.get("configurations"):
                indicator_dict = {
                    "id": "indicator--{}".format(str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))),
                    "created_by_ref": config.CVE2STIX_IDENTITY_REF.get("id"),
                    "created": datetime.strptime(
                        cve["published"], "%Y-%m-%dT%H:%M:%S.%f"
                    ),
                    "modified": datetime.strptime(
                        cve["lastModified"], "%Y-%m-%dT%H:%M:%S.%f"
                    ),
                    "indicator_types": ["compromised"],
                    "name": cve["id"],
                    "description": cve["descriptions"][0]["value"],
                    "pattern_type": "stix",
                    "valid_from": datetime.strptime(
                        cve["published"], "%Y-%m-%dT%H:%M:%S.%f"
                    ),
                    "object_marking_refs": [config.TLP_CLEAR_MARKING_DEFINITION_REF]+[config.CVE2STIX_MARKING_DEFINITION_REF.get("id")],
                    "external_references": cleanup([
                        {
                            "source_name": "cve",
                            "external_id": cve["id"],
                            "url": "https://nvd.nist.gov/vuln/detail/" + cve["id"],
                        },

                    ])
                }
                pattern_so_far, cpeIds = build_patterns_for_cve(cve["id"], cve.get("configurations", []), config)
                pattern = pattern_so_far.replace("\\", "\\\\")
                pattern = pattern.replace("\\\\'", "\\'")
                indicator_dict["pattern"] = pattern
            try:
                vulnerability = Vulnerability(**vulnerability_dict)
                config.fs.add(vulnerability)
            except Exception as e:
                logger.error(e)
                logger.error(vulnerability_dict)


            indicator = None
            relationship = None
            if indicator_dict:
                try:
                    #logger.info(f"Indicator => {indicator_dict}")
                    indicator = Indicator(**indicator_dict)
                    config.fs.add(indicator)
                    relationship = Relationship(
                        id="relationship--{}".format(str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))),
                        created=vulnerability["created"],
                        created_by_ref=config.CVE2STIX_IDENTITY_REF.get("id"),
                        modified=vulnerability["modified"],
                        relationship_type="identifies",
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
                    config.fs.add(relationship)
                except Exception as e:
                    logger.error(f"Indicator with issue -> CVE => {cve.get('id')}, Error: {str(e)}, Indicator Dict: {indicator_dict}")

            if cve.get("cisaVulnerabilityName"):
                report = Report(**{
                    "id": "report--{}".format(str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))),
                    "created_by_ref": config.CVE2STIX_IDENTITY_REF.get("id"),
                    "created": datetime.strptime(
                        cve["published"], "%Y-%m-%dT%H:%M:%S.%f"
                    ),
                    "modified": datetime.strptime(
                        cve["lastModified"], "%Y-%m-%dT%H:%M:%S.%f"
                    ),
                    "name": "CISA KEV: {}".format(cve.get("cisaVulnerabilityName")),
                    "description": "{} Action due by: {}".format(cve.get("cisaRequiredAction"),cve.get("cisaActionDue")),
                    "published": datetime.strptime(cve["published"],"%Y-%m-%dT%H:%M:%S.%f"),
                    "report_types": ["vulnerability"],
                    "object_refs": [
                        "vulnerability--{}".format(str(uuid.uuid5(config.namespace, f"{cve.get('id')}")))
                    ],
                    "object_marking_refs": [config.TLP_CLEAR_MARKING_DEFINITION_REF] + [config.CVE2STIX_MARKING_DEFINITION_REF.get("id")],
                    "external_references": [ {
                        "source_name": "cve",
                        "external_id": cve.get("id"),
                        "url": "https://nvd.nist.gov/vuln/detail/{}".format(cve.get('id'))
                    }
                    ]
                })
                config.fs.add(report)
            parsed_response +=[
                vulnerability.serialize()
            ]
            if indicator_dict and indicator != None:
                parsed_response.append(indicator.serialize())
            if relationship:
                parsed_response.append(relationship.serialize())
            if cve.get("cisaVulnerabilityName"):
                parsed_response.append(report.serialize())
        except:
            raise

    return parsed_response
