from datetime import date, datetime
import io
import json
from pytz import timezone
import requests
from stix2 import Software, Relationship, Indicator
from stix2extensions._extensions import software_cpe_properties_ExtensionDefinitionSMO
import urllib.request
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
    return dict(zip(['cpe_version', 'part', 'vendor', 'product', 'version', 'update', 'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other'], splits))

def parse_cpe_matches(indicator: Indicator) -> tuple[list[Software], list[Relationship]]:
    if not indicator:
        return [], []
    logging.info("parse cpe matches for %s", indicator.name)
    logging.info(f"{get_cpe_match.cache_info()}")
    softwares = {}
    relationships = []
    criteria_ids = {}
    for vv in indicator.x_cpes.get('vulnerable', []):
        criteria_ids[vv['matchCriteriaId']] = vv['criteria'], True
    for vv in indicator.x_cpes.get('not_vulnerable', []):
        criteria_ids[vv['matchCriteriaId']] = vv['criteria'], False

    for match_id, (matchstring, is_vulnerable) in criteria_ids.items():
        for cpe_name in get_cpe_match(matchstring):
            software = parse_software(cpe_name, None)
            softwares.setdefault(cpe_name, software)
            external_references = [
                {
                    "source_name": "cve",
                    "external_id": indicator.name,
                    "url": "https://nvd.nist.gov/vuln/detail/"+indicator.name,
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
            if is_vulnerable:
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


@lru_cache(maxsize=None)
def get_cpematch(criteria_id: str) -> list[tuple[str, str]]:
    criteria_id = criteria_id.upper()
    data = json.loads((config.MIRROR_DIRECTORY/"cpematch"/criteria_id[:2]/f'{criteria_id}.json').read_text())
    match = data['matchString']
    return [(cpe['cpeName'], cpe['cpeNameId']) for cpe in match.get("matches", [])]

@lru_cache(maxsize=None)
def get_cpe_match(match_string: str)  -> list[str]:
    matches = retrieve_cpematch(datetime.now(timezone('EST')).date())
    return matches.get(match_string, [match_string])

@lru_cache(maxsize=1)
def retrieve_cpematch(d: date):
    logging.info("Downloading CPEMatch Feed... %s", config.CPE_MATCH_FEED_URL)
    resp = requests.get(config.CPE_MATCH_FEED_URL)
    retval = {}
    logging.info("Downloaded CPEMatch Feed from %s", config.CPE_MATCH_FEED_URL)
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zip:
        with zip.open("nvdcpematch-1.0.json") as f:
            matches = ijson.items(f, 'matches.item')
            for count, match in enumerate(matches):
                match_spec = match["cpe23Uri"]
                retval[match_spec] = [m["cpe23Uri"] for m in match['cpe_name']]
            logging.info(f"retrieve_cpematch: {count=}, {len(retval)=}")
    return retval


@lru_cache(maxsize=1000)
def parse_software(cpename, swid):
    cpe_struct = cpe_name_as_dict(cpename)
    return Software(
        x_cpe_struct=cpe_struct,
        cpe=cpename,
        name=cpename,
        swid=swid,
        version=cpe_struct['version'],
        vendor=cpe_struct['vendor'],
        extensions={
            software_cpe_properties_ExtensionDefinitionSMO.id: {
                "extension_type": "toplevel-property-extension"
            }
        },
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3"
        ],
        allow_custom=True,
    )
