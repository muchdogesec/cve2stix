## STIX2 Mappings

### Marking Definition / Identity

These are hardcoded and imported from our [stix4doge repository](https://github.com/muchdogesec/stix4doge). Specifically these objects;

* Marking Definition: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/cve2stix.json
* Identity: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/cve2stix.json
* Extension Definition: https://raw.githubusercontent.com/muchdogesec/stix2extensions/refs/heads/main/extension-definitions/properties/software-cpe-properties.json

### Vulnerability SDOs

STIX 2.1 contains a Vulnerability SDO, [here is the specification for it](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_q5ytzmajn6re). In short, it is designed for modelling vulnerabilities, so I will use it for just that.

Using the response from the CVE API ([see the schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)) I can map the data in each CVE to the STIX 2.1 Vulnerability SDO;

```json
{
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--<UUIDv5 LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<vulnerabilities.cve.published>",
    "modified": "<vulnerabilities.cve.lastModified>",
    "name": "<vulnerabilities.cve.id>",
    "description": "<vulnerabilities.cve.descriptions.description_data.value> (if multiple, where lan = en, else first result)",
    "labels": [
        "<vulnerabilities.cve.cveTags>"
    ],
    "external_references": [
        {
            "source_name": "cve",
            "external_id": "<vulnerabilities.cve.id>",
            "url": "https://nvd.nist.gov/vuln/detail/<vulnerabilities.cve.id>"
        },
        {
            "source_name": "cwe",
            "external_id": "<vulnerabilities.cve.weaknesses.description.value[n]>",
            "url": "https://cwe.mitre.org/data/definitions/<vulnerabilities.cve.weaknesses.description.value[n]>.html"
        },
        { 
            "source_name": "<vulnerabilities.cve.references.source.[n]>",
            "url": "<vulnerabilities.cve.references.url.[n]>",
            "description": "<vulnerabilities.cve.references.tags.[n], vulnerabilities.cve.references.tags.[n]>"
        },
        { 
            "source_name": "<vulnerabilities.cve.references.source.[n]>",
            "url": "<vulnerabilities.cve.references.url.[n]>",
            "description": "<vulnerabilities.cve.references.tags.[n], vulnerabilities.cve.references.tags.[n]>"
        },
        {
            "source_name": "vulnStatus",
            "description": "<vulnStatus>"
        },
        {
            "source_name": "sourceIdentifier",
            "description": "<sourceIdentifier>"
        }
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<IMPORTED MARKING DEFINTION OBJECT>"
    ],
    "extensions": {
        "extension-definition--2c5c13af-ee92-5246-9ba7-0b958f8cd34a": {
            "extension_type": "toplevel-property-extension"
        }
    },
    "x_cvss": {
        "v3_1": {
            "baseScore": "<VALUE>",
            "baseSeverity": "<VALUE>",
            "exploitabilityScore":"<VALUE>",
            "impactScore": "<VALUE>",
            "vectorString": "<VALUE>",
            "source": "<VALUE>",
            "type": "<VALUE>"
        }
    }
}
```

Note, due to CVSS scoring changes, not all CVEs have all versions of CVSS Scoring. e.g. very old CVEs (pre-2020 ish) often only have CVSS v2 scores. This is reflected in the object keys (e.g. `3_1` = CVSS 3.1).

To generate the id of the object, a UUIDv5 is generated using the namespace `562918ee-d5da-5579-b6a1-fae50cc6bad3` and the `CVE ID`

e.g `CVE-2019-18939` = `37f8739d-1702-5e39-bc7e-d0710e06487a` = `vulnerability--37f8739d-1702-5e39-bc7e-d0710e06487a`

As we are using custom properties, we define them using an extension defintion;

https://raw.githubusercontent.com/muchdogesec/stix2extensions/main/extension-definitions/properties/vulnerability-scoring.json

This extension definition is imported and stored in each bundle generated.

#### A note on rejected CVEs

Sometime CVEs are revoked for a variety of reasons. See: https://nvd.nist.gov/vuln/vulnerability-status

When a CVE is revoked, the `vulnStatus` becomes `REJECT` in an update. In which case a `revoked` property is included in the Vulnerability SDO with its value set to `true`.

### Indicator SDOs

The CVE Vulnerability Object (which defines what CPE is actually vulnerable can be thought of like a description of the CVE, cve2stix also uses the [STIX 2.1 Indicator SDO](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633) to provide a logical pattern to describe the products (and configorations) the CVE affects.

STIX 2.1 Indicator Objects contain STIX Patterns that can be used to describe the CPE configuration logic defined in the CVE.

The `pattern` object inside an Indicator is always constructed from [STIX Software SCOs](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070740) CPE property (`software.cpe`.

For example, if the CVE contained a simple node configuration with the following CPE URI `cpe:2.3:o:tesla:model_3_firmware:-:*:*:*:*:*:*:*` the pattern would read;

```json
    "pattern": "[software.cpe = 'cpe:2.3:o:tesla:model_3_firmware:-:*:*:*:*:*:*:*']",
```

The logic to create the pattern is based on the node configurations inside the CVE (the operators used `AND`, `OR`, and parenthesis). You can read the logic cve2stix uses to generate the `pattern` in `docs/cpe-pattern-logic.md`

Here is the structure of the Indicator SDO and how cve2stix populates it;

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<SAME UUID AS VULNERABILITY SDO>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<vulnerabilities.cve.published>",
    "modified": "<vulnerabilities.cve.lastModifiedDate>",
    "indicator_types": [
        "compromised"
    ],
    "name": "<vulnerability.id>",
    "description": "vulnerabilities.cve.description.description_data.value> (if multiple, where lan = en, else first result)",
    "pattern": "(<CPE PATTERN [1]>) OR (<CPE PATTERN [N]>)",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "valid_from": "<vulnerabilities.cve.publishedDate>",
    "external_references": [
        {
            "source_name": "cve",
            "external_id": "<vulnerabilities.cve.id>",
            "url": "https://nvd.nist.gov/vuln/detail/<vulnerabilities.cve.id>"
        },
        {
            "source_name": "vulnerable_cpe",
            "external_id": "<cpe_id>",
        }
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<IMPORTED MARKING DEFINTION OBJECT>"
    ],
    "extensions": {
        "extension-definition--ad995824-2901-5f6e-890b-561130a239d4": {
            "extension_type": "toplevel-property-extension"
        }
    },
    "x_cpes": {
        "not_vulnerable": [
            {
                "criteria": "<vulnerabilities.cve.configurations.nodes.cpeMatch.criteria (where vulnerable = true>",
                "matchCriteriaId": "<vulnerabilities.cve.configurations.nodes.cpeMatch.matchCriteriaId (where vulnerable = true>"
            }
        ],
        "vulnerable": [
            {
                "criteria": "<vulnerabilities.cve.configurations.nodes.cpeMatch.criteria (where vulnerable = false>",
                "matchCriteriaId": "<vulnerabilities.cve.configurations.nodes.cpeMatch.matchCriteriaId (where vulnerable = false>"
            }
        ]
    }
}
```

Note, the UUID of the Indicator is the same as the Vulnerability for easier identification.

Note, a CVE can have zero or more match patterns. In cve2stix a Vulnerability SDO only ever has one Indicator SDO linked to it. In this case each match pattern is joined using an `OR` statement in the pattern field.

As we are using custom properties, we define them using an extension defintion;

https://raw.githubusercontent.com/muchdogesec/stix2extensions/main/extension-definitions/properties/indicator-vulnerable-cpes.json

### Indicator -> Vulnerabily Relationship

Now that the CVE is modelled as a STIX Vulnerability and STIX Indicator Objects the relationship between them needs to be defined.

cve2stix uses [STIX Relationship SROs](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070673) to do this. They are structured like so;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<VULNERABILITY SDO ID>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<vulnerabilities.cve.published>",
    "modified": "<vulnerabilities.cve.lastModifiedDate>",
    "relationship_type": "cpe-match",
    "source_ref": "vulnerability--<VULNERABILITY STIX OBJECT>",
    "target_ref": "indicator--<INDICATOR STIX OBJECT>",
    "description": "<CVE-ID> affects products identified by the CPEs in the Indicator objects pattern",
    "external_references": [
        {
            "source_name": "cve",
            "external_id": "<vulnerabilities.cve.id>",
            "url": "https://nvd.nist.gov/vuln/detail/<vulnerabilities.cve.id>"
        }
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<IMPORTED MARKING DEFINTION OBJECT>"
    ]
}
```

## Indicator -> Grououng

Inside the Indicator is `x_cpes` property, e.g. 

```json
    "x_cpes": {
        "not_vulnerable": [
            {
                "criteria": "cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*",
                "matchCriteriaId": "86619D7A-ACB6-489C-9C29-37C6018E5B4B"
            }
        ],
        "vulnerable": [
            {
                "criteria": "cpe:2.3:o:tesla:model_s_firmware:*:*:*:*:*:*:*:*",
                "matchCriteriaId": "FD68704D-C711-491F-B278-B02C6866738C"
            }
        ]
    }
```

These define what CPEs a are vulnerable in the pattern.

Not a CPE `criteria` might have more than one CPE linked to it.

You can identify this using the [CPE Match Criteria API](https://nvd.nist.gov/developers/products) e.g. `86619D7A-ACB6-489C-9C29-37C6018E5B4B`

```json
        {
            "matchString": {
                "matchCriteriaId": "86619D7A-ACB6-489C-9C29-37C6018E5B4B",
                "criteria": "cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*",
                "versionEndIncluding": "2022-03-26",
                "lastModified": "2022-10-05T14:00:34.840",
                "cpeLastModified": "2022-10-05T14:00:34.840",
                "created": "2022-04-04T12:37:32.813",
                "status": "Active",
                "matches": [
                    {
                        "cpeName": "cpe:2.3:o:tesla:model_3_firmware:-:*:*:*:*:*:*:*",
                        "cpeNameId": "979F9EB6-C9F6-49EE-9FED-2ED17E400E86"
                    },
                    {
                        "cpeName": "cpe:2.3:o:tesla:model_3_firmware:11.0:*:*:*:*:*:*:*",
                        "cpeNameId": "62DCA7AD-A796-486F-8FB6-DEACC078D402"
                    },
                    {
                        "cpeName": "cpe:2.3:o:tesla:model_3_firmware:2022-03-26:*:*:*:*:*:*:*",
                        "cpeNameId": "F010C8B7-83E9-45FB-A5D4-26EDF34EC312"
                    }
                ]
            }
        }
```

Using the `cpeNameId`s in the CVE a software object can be created as follows;

```json
{
    "type": "software",
    "spec_version": "2.1",
    "id": "software--<GENERATED BY STIX2 LIBRARY>",
    "name": "<products.cpe.cpeName>",
    "cpe": "<products.cpe.cpeName>",
    "swid": "<products.cpe.cpeId>",
    "version": "<products.cpe.cpeName[version_section]>",
    "vendor": "<products.cpe.cpeName[vendor_section]>",
    "languages": [
        "<products.cpe.titles.lang>"
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<IMPORTED MARKING DEFINTION OBJECT>"
    ],
    "extensions": {
        "extension-definition--82cad0bb-0906-5885-95cc-cafe5ee0a500": {
            "extension_type": "toplevel-property-extension"
        }
    },
    "x_cpe_struct": {
        "cpe_version": "<CPE_VERSION>",
        "part": "<PART>",
        "vendor": "<VENDOR>",
        "product": "<PRODUCT>",
        "version": "<VERSION>",
        "update": "<UPDATE>",
        "edition": "<EDITION>",
        "language": "<LANGUAGE>",
        "sw_edition": "<SW_EDITION>",
        "target_sw": "<TARGET_SW>",
        "target_hw": "<TARGET_HW>",
        "other": "<OTHER>"
    }
}
```

Using the `matchCriteriaId` a `grouping` object can be created as follows:

```json
{
    "type": "grouping",
    "spec_version": "2.1",
    "id": "grouping--<UUID V5>",
    "created_by_ref": "identity--152ecfe1-5015-522b-97e4-86b60c57036d",
    "created": "<matchstring.created>",
    "modified": "<matchstring.lastModified>",
    "name": "<matchstring>",
    "revoked": "<is false if matchstring.status is not Active>",
    "context": "unspecified",
    "object_refs": [
        "software--<ALL SOFTWARE OBJECTS CREATED THAT BELONG IN MATCH CRITERIA>"
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d"
    ],
    "external_references": [
        {
            "source_name": "matchCriteriaId",
            "external_id": "<matchCriteriaId>"
        },
        {
            "source_name": "pattern",
            "external_id": "<matchstring>"
        },
        {
            "source_name": "versionStartIncluding",
            "external_id": "<versionStartIncluding>"
        },
        {
            "source_name": "versionStartExcluding",
            "external_id": "<versionStartExcluding>"
        },
        {
            "source_name": "versionEndIncluding",
            "external_id": "<versionEndIncluding>"
        },
        {
            "source_name": "versionEndExcluding",
            "external_id": "<versionEndExcluding>"
        }
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `152ecfe1-5015-522b-97e4-86b60c57036d` and the `matchstring` values.

### Indictor -> Grouping

Note, a relationship object is not needed to connect Grouping to Softwares, as this is covered in object_refs

A relationship between the Indicator and corresponding Grouping object is made and represented as follows;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUID V5 LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<grouping created>",
    "modified": "<grouping modified>",
    "relationship_type": "<x-cpes-vulnerable> OR <x-cpes-not-vulnerable>",
    "source_ref": "indicator--<INDICATOR STIX OBJECT>",
    "target_ref": "grouping--<GROUPING TIX OBJECT>",
    "description": "<matchCriteriaId> <is vulnerable to> <is not vulnerable> to <Indicator name>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ],
    "external_references": [
        {
            "source_name": "cve",
            "external_id": "<vulnerabilities.cve.id>",
            "url": "https://nvd.nist.gov/vuln/detail/<vulnerabilities.cve.id>"
        },
        {
            "source_name": "cpe",
            "external_id": "matchCriteriaId"
        },
        {
            "source_name": "pattern",
            "external_id": "<matchstring>"
        }
    ]
}
```

`relationship_type`/`description` is determined by the Indicator `x_cpes.not_vulnerable` or `x_cpes.vulnerable` logic

To generate the id of SRO, a UUIDv5 is generated using the namespace `562918ee-d5da-5579-b6a1-fae50cc6bad3` and the `relationship_type+source_ref+target_ref` values.


### Bundle

```json
{
    "type": "bundle",
    "id": "bundle--<UUIDV5 GENERATION LOGIC>",
    "objects": [
        "<ALL STIX JSON OBJECTS>"
    ]
}
```

To generate the id of the SRO, a UUIDv5 is generated using the namespace `562918ee-d5da-5579-b6a1-fae50cc6bad3` and an md5 hash of all the sorted objects in the bundle.
