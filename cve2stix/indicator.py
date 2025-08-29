import uuid
from stix2 import Vulnerability, Indicator, Relationship
from .config import DEFAULT_CONFIG as config
from stix2extensions._extensions import (
    indicator_vulnerable_cpes_ExtensionDefinitionSMO,
)

from cve2stix.utils import unescape_cpe_string


def parse_cve_indicator(
    cve: dict, vulnerability: Vulnerability
) -> "tuple[Indicator, Relationship]|None":
    if not cve.get("configurations"):
        return None
    cpe_names, pattern_so_far, cpeIds = build_patterns_for_cve(
        cve["id"], cve.get("configurations", [])
    )

    indicator_dict = {
        "id": "indicator--{}".format(
            str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))
        ),
        "created_by_ref": config.CVE2STIX_IDENTITY_REF.get("id"),
        "created": vulnerability.created,
        "modified": vulnerability.modified,
        "indicator_types": ["compromised"],
        "name": cve["id"],
        "description": vulnerability.description,
        "pattern_type": "stix",
        "pattern": pattern_so_far,
        "valid_from": vulnerability.created,
        "object_marking_refs": [config.TLP_CLEAR_MARKING_DEFINITION_REF]
        + [config.CVE2STIX_MARKING_DEFINITION_REF.get("id")],
        "extensions": {
            indicator_vulnerable_cpes_ExtensionDefinitionSMO.id: {
                "extension_type": "toplevel-property-extension"
            }
        },
        "x_cpes": cpe_names,
        "external_references": [
            {
                "source_name": "cve",
                "external_id": cve["id"],
                "url": "https://nvd.nist.gov/vuln/detail/" + cve["id"],
            },
        ],
    }
    indicator = Indicator(**indicator_dict)
    relationship = Relationship(
        id="relationship--{}".format(
            str(uuid.uuid5(config.namespace, f"{cve.get('id')}"))
        ),
        created=vulnerability["created"],
        created_by_ref=config.CVE2STIX_IDENTITY_REF.get("id"),
        modified=vulnerability["modified"],
        description=f"The Indicator contains a pattern that detects {indicator.name}",
        relationship_type="x-cpe-match",
        source_ref=indicator,
        target_ref=vulnerability,
        object_marking_refs=[config.TLP_CLEAR_MARKING_DEFINITION_REF]
        + [config.CVE2STIX_MARKING_DEFINITION_REF.get("id")],
        external_references=[
            {
                "source_name": "cve",
                "external_id": cve.get("id"),
                "url": "https://nvd.nist.gov/vuln/detail/{}".format(cve.get("id")),
            }
        ],
    )
    return [indicator, relationship]


def build_patterns_for_cve(cve_id: str, pattern_configurations):
    patterns = []
    vulnerable_cpe_names = []
    non_vulnerable_cpes = []
    cpe_names_all = []
    JOINER = " OR "

    for pconfig in pattern_configurations:
        pconfig_operator = " {} ".format(pconfig.get("operator", JOINER).strip())
        node_patterns = []
        for node in pconfig.get("nodes"):
            node_operator = " {} ".format(node.get("operator", JOINER).strip())
            node_matches = []
            for match in node.get("cpeMatch", []):
                node_matches.append(
                    f"software:cpe={unescape_cpe_string(match['criteria'])}"
                )
                cpe_match = dict(
                    criteria=match["criteria"], matchCriteriaId=match["matchCriteriaId"]
                )
                if match.get("vulnerable"):
                    vulnerable_cpe_names.append(cpe_match)
                else:
                    non_vulnerable_cpes.append(cpe_match)
            node_patterns.append("[{}]".format(node_operator.join(node_matches)))

        patterns.append("({})".format(pconfig_operator.join(node_patterns)))
    return (
        dict(not_vulnerable=non_vulnerable_cpes, vulnerable=vulnerable_cpe_names),
        JOINER.join(patterns),
        cpe_names_all,
    )
