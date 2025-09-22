from stix2 import Software, Relationship, Indicator, Grouping

from cve2stix.utils import fetch_url
from .config import DEFAULT_CONFIG as config
import logging
from stix2.patterns import StringConstant
from arango_cve_processor.tools.cpe import relate_indicator, parse_objects_for_criteria


def unescape_cpe_string(cpe_string):
    return str(StringConstant(cpe_string))


def get_matches_for_cve(cve_id):
    criteria_data = []

    def parse(response, *args):
        for match_data in response.get("matchStrings", []):
            criteria_data.append(match_data["matchString"])

    fetch_url(
        url=config.CPE_MATCH_FEED_URL + f"?cveId={cve_id}",
        config=config,
        callback=parse,
    )
    return criteria_data


def parse_cpe_matches(
    indicator: Indicator,
) -> tuple[list[Grouping], list[Software], list[Relationship]]:
    if not indicator:
        return [], [], []
    logging.info("parse cpe matches for %s", indicator.name)
    softwares = {}
    relationships = []
    groupings = []

    for match_data in get_matches_for_cve(cve_id=indicator.name):
        objects = parse_objects_for_criteria(match_data)
        softwares.update({obj["id"]: obj for obj in objects[1:]})
        groupings.append(objects[0])
        relationships.extend(relate_indicator(objects[0], indicator))
    return groupings, list(softwares.values()), relationships
