from datetime import date, datetime
import io
import json
from pytz import timezone
import requests
from stix2 import Software, Relationship, Indicator
from stix2extensions._extensions import software_cpe_properties_ExtensionDefinitionSMO
import urllib.request

from cve2stix.utils import fetch_url
from .config import DEFAULT_CONFIG as config
from functools import lru_cache
import logging
import json
import re
import logging
from stix2.patterns import StringConstant
import zipfile, ijson


def unescape_cpe_string(cpe_string):
    return str(StringConstant(cpe_string))


def split_cpe_name(cpename: str) -> list[str]:
    """
    Split CPE 2.3 into its components, accounting for escaped colons.
    """
    non_escaped_colon = r"(?<!\\):"
    split_name = re.split(non_escaped_colon, cpename)
    return split_name


def cpe_name_as_dict(cpe_name: str) -> dict[str, str]:
    splits = split_cpe_name(cpe_name)[1:]
    return dict(
        zip(
            [
                "cpe_version",
                "part",
                "vendor",
                "product",
                "version",
                "update",
                "edition",
                "language",
                "sw_edition",
                "target_sw",
                "target_hw",
                "other",
            ],
            splits,
        )
    )


class CpeMatchGetter:
    matches = {}

    @classmethod
    def get_matches_for_cve(cls, cve_id, criteria_ids):
        if not set(cls.matches).issuperset({c[1] for c in criteria_ids}):
            fetch_url(
                url=config.CPE_MATCH_FEED_URL + f"?cveId={cve_id}",
                config=config,
                callback=cls.parse_response,
            )
        return [
            (criteria_id, cls.matches.get(criteria_id, []))
            for match_string, criteria_id in criteria_ids
        ]

    @classmethod
    def parse_response(cls, response, *args):
        for match_data in response.get("matchStrings", []):
            match_data = match_data["matchString"]
            criteria_id = match_data["matchCriteriaId"]
            cpes = cls.matches[criteria_id] = []
            for cpe in match_data.get("matches", []):
                cpes.append((cpe["cpeName"], cpe["cpeNameId"]))


def parse_cpe_matches(
    indicator: Indicator,
) -> tuple[list[Software], list[Relationship]]:
    if not indicator:
        return [], []
    logging.info("parse cpe matches for %s", indicator.name)
    softwares = {}
    relationships = []

    vulnerable_criteria_ids = []
    all_criteria_ids = []
    for vv in indicator.x_cpes.get("vulnerable", []):
        vulnerable_criteria_ids.append(vv["matchCriteriaId"])
        all_criteria_ids.append((vv["criteria"], vv["matchCriteriaId"]))
    for vv in indicator.x_cpes.get("not_vulnerable", []):
        all_criteria_ids.append((vv["criteria"], vv["matchCriteriaId"]))

    for match_id, matches in CpeMatchGetter.get_matches_for_cve(
        cve_id=indicator.name, criteria_ids=all_criteria_ids
    ):
        for cpe_name, swid in matches:
            software = parse_software(cpe_name, None)
            softwares.setdefault(cpe_name, software)
            external_references = [
                {
                    "source_name": "cve",
                    "external_id": indicator.name,
                    "url": "https://nvd.nist.gov/vuln/detail/" + indicator.name,
                },
                {
                    "source_name": "cpe",
                    "external_id": cpe_name,
                    # "url": "https://nvd.nist.gov/products/cpe/detail/"+swid,
                },
            ]
            relationships.append(
                Relationship(
                    source_ref=indicator.id,
                    target_ref=software.id,
                    created=indicator.created,
                    modified=indicator.modified,
                    relationship_type="relies-on",
                    description=f"{indicator.name} relies on {software.cpe}",
                    created_by_ref=indicator.created_by_ref,
                    object_marking_refs=indicator.object_marking_refs,
                    external_references=external_references,
                )
            )
            if match_id in vulnerable_criteria_ids:
                relationships.append(
                    Relationship(
                        source_ref=indicator.id,
                        target_ref=software.id,
                        created=indicator.created,
                        modified=indicator.modified,
                        relationship_type="exploits",
                        description=f"{indicator.name} exploits {software.cpe}",
                        created_by_ref=indicator.created_by_ref,
                        object_marking_refs=indicator.object_marking_refs,
                        external_references=external_references,
                    )
                )

    return list(softwares.values()), relationships


@lru_cache(maxsize=1000)
def parse_software(cpename, swid):
    cpe_struct = cpe_name_as_dict(cpename)
    return Software(
        x_cpe_struct=cpe_struct,
        cpe=cpename,
        name=cpename,
        swid=swid,
        version=cpe_struct["version"],
        vendor=cpe_struct["vendor"],
        extensions={
            software_cpe_properties_ExtensionDefinitionSMO.id: {
                "extension_type": "toplevel-property-extension"
            }
        },
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
        ],
        allow_custom=True,
    )
