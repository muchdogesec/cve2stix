# cve2stix

## Before you begin

We host a full web API that includes all objects created by cve2stix, [Vulmatch](https://www.vulmatch.com/).

## Overview

![](docs/cve2stix.png)

A command line tool that turns NVD CVE records into STIX 2.1 Objects.

> The mission of the CVE® Program is to identify, define, and catalog publicly disclosed cybersecurity vulnerabilities. There is one CVE Record for each vulnerability in the catalog. The vulnerabilities are discovered then assigned and published by organizations from around the world that have partnered with the CVE Program. Partners publish CVE Records to communicate consistent descriptions of vulnerabilities. Information technology and cybersecurity professionals use CVE Records to ensure they are discussing the same issue, and to coordinate their efforts to prioritize and address the vulnerabilities.

Source: https://www.cve.org/About/Overview

CVE records are currently published to the NVD API, but are in a custom schema.

We had a requirement to have an up-to-date copy of NVD CVEs in STIX 2.1 format for easy dissemination to downstream system.

The code in this repository turns CVEs into STIX 2.1 objects, and keeps them updated to match the official CVE API;

1. Downloads the current CVEs (that match a users filters) from an [NVD API mirror](https://github.com/espressif/esp-nvd-mirror/)
2. Converts them to STIX 2.1 Objects
3. Stores the STIX 2.1 Objects in the file store
4. Creates STIX Bundles of generated objects for each update run

## tl;dr

[![cve2stix](https://img.youtube.com/vi/j8DWB7QF95g/0.jpg)](https://www.youtube.com/watch?v=j8DWB7QF95g)

[Watch the demo](https://www.youtube.com/watch?v=j8DWB7QF95g).

## Install the script

```shell
# clone the latest code
git clone https://github.com/muchdogesec/cve2stix
# create a venv
cd cve2stix
python3 -m venv cve2stix-venv
source cve2stix-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
```

You will also need to have redis installed on your machine. [Instructions to do this are here](https://redis.io/docs/getting-started/installation/).

If you're on Mac, like me, the easiest way to do this is;

```shell
brew install redis
```

### Configuration options

cve2stix has various settings that are defined in an `.env` file.

To create a template for the file:

```shell
cp .env.example .env
```

To see more information about how to set the variables, and what they do, read the `.env.markdown` file.

## Running the script

The script runs Redis and Celery jobs to download the data, you must start this first.

Generally you want to run these in a seperate terminal window but still in the a `cve2stix-venv`.

```shell
# navigate to the root of cve2stix install
cd cve2stix
# activate venv
source cve2stix-venv/bin/activate
# restart redis
brew services restart redis
# start celery
celery -A cve2stix.celery worker --loglevel=info --purge
```

If you continually run into issues, you can also use flower to monitor Celery workers for debugging. In a new terminal run;

```shell 
celery -A cve2stix.celery flower
```

To open the application. You can also use Docker to run flower, [as detailed here](https://flower.readthedocs.io/en/latest/install.html#usage).

The script to get CVEs can now be executed (in the second terminal window) using;

```shell
python3 cve2stix.py
```

It will also filter the data created using any values entered in the `.env` file on each run.

On each run, the old `stix2_objects/cve-bundle.json` will be overwritten. 

On each run it is vital you shutdown the celery workers before restarting and running the job again.

```shell
^C
worker: Hitting Ctrl+C again will terminate all running tasks!

worker: Warm shutdown (MainProcess)
```

Don't forget to restart the workers again, as follows;

```shell
# start celery
celery -A cve2stix.celery worker --loglevel=info --purge
```

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
    "relationship_type": "detects",
    "source_ref": "indicator--<INDICATOR STIX OBJECT>",
    "target_ref": "vulnerability--<VULNERABILITY STIX OBJECT>",
    "description": "The Indicator contains a pattern that detects <cve.id>",
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

## Indicator -> Software

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

You can identify this using the [CPE Match Criteria data](https://github.com/espressif/esp-nvd-mirror/tree/master/cpematch) e.g. `86619D7A-ACB6-489C-9C29-37C6018E5B4B`

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
    "name": "<products.cpe.titles.title> (if multiple, where lan = en, else first result)",
    "cpe": "<products.cpe.cpeName>",
    "swid": "<products.cpe.cpeNameId>",
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

### Indictor -> Software (all software objects)

A relationship between the Indicator and corresponding Software object is made and represented as follows;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUID V5 LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<vulnerabilities.cve.published>",
    "modified": "<vulnerabilities.cve.lastModifiedDate>",
    "relationship_type": "pattern-contains",
    "source_ref": "indicator--<INDICATOR STIX OBJECT>",
    "target_ref": "software--<SOFTWARE STIX OBJECT>",
    "description": "<Indicator name> <relationship_type without - char> <CPE ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `562918ee-d5da-5579-b6a1-fae50cc6bad3` and the `relationship_type+source_ref+target_ref` values.

### Indictor -> Software (`x_cpes.vulnerable` vulnerable software objects only)

A relationship between the Indicator and corresponding Software object is made and represented as follows;

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUID V5 LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<vulnerabilities.cve.published>",
    "modified": "<vulnerabilities.cve.lastModifiedDate>",
    "relationship_type": "is-vulnerable",
    "source_ref": "indicator--<INDICATOR STIX OBJECT>",
    "target_ref": "software--<SOFTWARE STIX OBJECT>",
    "description": "<Indicator name> <relationship_type without - char> <CPE ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of SRO, a UUIDv5 is generated using the namespace `562918ee-d5da-5579-b6a1-fae50cc6bad3` and the `relationship_type+source_ref+target_ref` values.

### Bundle

All objects will be packed into a bundle file in `stix2_objects` names `cve-bundle.json` which has the following structure.

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

### Updating STIX Objects

New CVEs are added daily. Existing CVEs are also updated as changes are logged.

Therefore the script can be used to keep an up-to-date copy of objects.

Generally it is assumed the script will be used like so;

1. on install, a user will create a backfill of all CVEs (almost 230,000 at the time of writing, depending on `CVE_LAST_MODIFIED_EARLIEST`/`CVE_LAST_MODIFIED_LATEST` date used)
    * note, generally this job will be split into multiple parts, downloading one month of data at a time.
2. said bundle(s) will be imported to some downstream tool (e.g. a threat intelligence platform)
3. the user runs the script again, this time updating the `CVE_LAST_MODIFIED_EARLIEST` .env variable to match the last time script is run (so that updated bundle only captures new and update objects)

The script will store the STIX objects created in the `stix2_objects` directory. All old objects will be purged with each run.

## Recommendations for backfill

I STRONGLY recommend you [use cxe2stix_helper to perform the backfill](https://github.com/muchdogesec/cxe2stix_helper). cxe2stix_helper will handle the splitting of the bundle files into your desired time ranges.

## Useful supporting tools

* To generate STIX 2.1 Objects: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* The STIX 2.1 specification: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
* [NVD CVE Overview](https://nvd.nist.gov/vuln)
* [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities)

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).