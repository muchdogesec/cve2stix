import calendar
import logging
import os
import argparse
import subprocess
import sys
import time
from cve2stix.config import Config
from cve2stix.main import main as download_bundle
from cve2stix.celery import check_online_status, start_celery
import argparse
import logging
from pathlib import Path
import re
from datetime import datetime as dt, timedelta
import subprocess
import sys
import calendar
import time
import os
import dotenv

dotenv.load_dotenv()

def valid_date(s):
    try:
        return dt.strptime(s, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        msg = f"Not a valid date: {s}. Please use the format `YYYY-MM-DDThh:mm:ss`."
        raise argparse.ArgumentTypeError(msg)

def parse_time_range(s):
    UNITS = "d", "m", "y"
    match = re.match(r'(\d+)(\w+)', s)
    try:
        num, unit = match.groups()
        unit = unit.lower()
    except BaseException:
        raise argparse.ArgumentTypeError(f"Could not parse `{s}`: should be in format `2d|1m|6m|1y`")
    if unit[0] not in UNITS:
        raise argparse.ArgumentTypeError(f"{s} -- unrecognized time unit: {unit}")
    if int(num) == 0:
        raise argparse.ArgumentTypeError(f"Prefix cannot be zero or negative: {s}")
    return s


def parse_args():
    parser = argparse.ArgumentParser(description="Helper script for converting CVE and CPE data to STIX format.", allow_abbrev=True)
    parser.add_argument("--last_modified_earliest", help="Earliest date for last modified filter", metavar="YYYY-MM-DDThh:mm:ss", required=True, type=valid_date)
    latest = parser.add_argument("--last_modified_latest", help="Latest date for last modified filter", metavar="YYYY-MM-DDThh:mm:ss", required=True, type=valid_date)
    parser.add_argument("--file_time_range", help="Time range for file processing (e.g., 1m)", default="1m", type=parse_time_range)
    
    args = parser.parse_args()

    if args.last_modified_latest < args.last_modified_earliest:
        raise argparse.ArgumentError(latest, "--last_modified_latest must not be earlier than --last_modified_earliest")

    return args

def get_time_ranges(s, earliest: dt, latest: dt) -> list[tuple[dt, dt]]:
    ONEDAY = timedelta(days=1)
    ONESEC = timedelta(seconds=1)
    match = re.match(r'(\d+)(\w+)', s)
    num, unit = match.groups()
    num = int(num)
    output = []
    unit = unit[0]
    hi = earliest
    while hi < latest:
        lo = hi
        for _ in range(num):
            if unit == 'm':
                _, days_in_month = calendar.monthrange(hi.year, hi.month)
                hi = hi.replace(day=days_in_month, hour=23, minute=59, second=59)
            if unit == 'd':
                hi += ONEDAY
            if unit == 'y':
                hi = dt(hi.year, 12, 31, 23, 59, 59)
            hi += ONESEC
        hi -= ONEDAY
        hi = hi.replace(hour=23, minute=59, second=59)
        if hi >= latest:
            hi = latest
        output.append((unit, lo, hi))
        hi += ONESEC
    return output


def run():
    check_online_status()
    args = parse_args()

    celery_process = start_celery("cve2stix.celery")
    check_online_status()

    PARENT_PATH = Path("./output").absolute()
    OBJECTS_PARENT = PARENT_PATH / "objects"
    BUNDLE_PATH = PARENT_PATH / "bundles"

    for time_unit, start_date, end_date in get_time_ranges(args.file_time_range, args.last_modified_earliest, args.last_modified_latest):
        start_day, end_day = start_date.strftime('%Y_%m_%d-%H_%M_%S'), end_date.strftime('%Y_%m_%d-%H_%M_%S')
        subdir = start_date.strftime('%Y-%m') if time_unit == 'd' else start_date.strftime('%Y')
        file_system = OBJECTS_PARENT / f"cve_objects-{start_day}-{end_day}"
        file_system.mkdir(parents=True, exist_ok=True)
        bundle_name = f"{subdir}/cve-bundle-{start_day}-{end_day}.json"
        (BUNDLE_PATH / bundle_name).parent.mkdir(parents=True, exist_ok=True)

        download_bundle(
            start_date,
            end_date,
            filename=bundle_name,
            config=Config(
                start_date=start_date,
                end_date=end_date,
                stix2_objects_folder=str(file_system),
                file_system=str(file_system),
                stix2_bundles_folder=str(BUNDLE_PATH),
                nvd_api_key=os.getenv("NVD_API_KEY")
            ),
        )
    
    celery_process.kill()

if __name__ == "__main__":
    run()