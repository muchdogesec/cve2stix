"""
Representation of CVE object stored in stix2_bundles/
"""

from dataclasses import dataclass, field
from typing import List
from stix2 import Vulnerability, Software, Indicator, Relationship

@dataclass
class CVE:
    vulnerability: Vulnerability
    indicator: "Indicator | None" = None
    # CVE relationship between vulnerability and indicator
    identifies_relationship: "Relationship | None" = None
    softwares: List[Software] = field(default_factory=list)

