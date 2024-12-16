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

The script to get CVEs can now be executed (in the second terminal window) using;

```shell
python3 cve2stix.py \
    --last_modified_earliest date \
    --last_modified_latest date \
    --file_time_range dictionary
```

* `last_modified_earliest` (required, date in format `YYYY-MM-DDThh:mm:ss`): earliest modified data 
    * default: none
* `last_modified_latest` (required, date in format `YYYY-MM-DDThh:mm:ss`): used in the the cve2stix/cpe2stix config
    * default: none
* `file_time_range` (required): defines how much data should be packed in each output bundle. Use `d` for days, `m` for months, `y` for years. Note, if no results are found for a time period, a bundle will not be generated. This usually explains why you see "missing" bundles for a day or month. 
    * default `1d` (1 day)

IMPORTANT: if the time between `--last_modified_earliest` and `--last_modified_latest` is greater than 120 days and you select `--file_time_range` = `1y`, the script will batch celery jobs with different `lastModStartDate` and `lastModEndDate` as NVD only allows for a range of 120 days to be specified in a request.

The script will also filter the data created using any values entered in the `.env` file on each run.

e.g. get all cves for June 2024 (and place into daily bundles)

```shell
python3 cve2stix.py \
    --last_modified_earliest 2024-11-01T00:00:00 \
    --last_modified_latest 2024-11-30T23:59:59 \
    --file_time_range 1d
```

Will generate bundle files in directories as follows:

```txt
output
└── bundles
    ├── cve-bundle-2024_08_01-00_00_00-2024_08_01-23_59_59.json
    ├── cve-bundle-2024_08_02-00_00_00-2024_08_02-23_59_59.json
    ├── cve-bundle-2024_08_03-00_00_00-2024_08_03-23_59_59.json
    ├── ...
```

Note, it is possible to have missing gaps in the data. This just means no CVE had a modified time between that time range. This is especially true when running across larger periods of time.

### IMPORTANT NOTE ON BACKFILLING DATA

Between 2024-11-19 and 2024-11-21 most of the NVD dataset was modified as part of adding support for ADP data.

You can read more about this at https://www.nist.gov/itl/nvd#november1524.

This is problematic for us, as will result in huge bundles using the normal `modDate` approach.

As such, we have build in the `--all_time` flag to handle this data more graciously. All time mode uses `pubDate` instead of `modDate` to bundle the files. This will start the run from 1988 (first CVE `pubDate` though to day script is executed).

## Useful supporting tools

* To generate STIX 2.1 Objects: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* The STIX 2.1 specification: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
* [NVD CVE Overview](https://nvd.nist.gov/vuln)
* [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities)

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).