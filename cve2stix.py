import calendar
import logging
import os
import argparse
import subprocess
import sys
import time
from cve2stix.config import Config, FilterMode
from cve2stix.main import main as download_bundle
from cve2stix.celery import check_online_status, start_celery
import argparse
import logging
from pathlib import Path
import re
from datetime import datetime as dt, timedelta, timezone
import subprocess
import sys
import calendar
import time
import os
import dotenv
from tqdm import tqdm

dotenv.load_dotenv()

PUB_START_DATE = dt(1988, 10, 1, tzinfo=timezone.utc)

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

class _HelpAction(argparse._HelpAction):

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()

        # retrieve subparsers from parser
        subparsers_actions = [
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)]
        # there will probably only be one subparser_action,
        # but better save than sorry
        for subparsers_action in subparsers_actions:
            # get all subparsers and print help
            for choice, subparser in subparsers_action.choices.items():
                print(" ========= Mode '{}' ========= ".format(choice))
                print(subparser.format_help())

        parser.exit()

def parse_args():
    parser = argparse.ArgumentParser(description="Helper script for converting CVE and CPE data to STIX format.", allow_abbrev=True, add_help=False)
    parser.add_argument('--help', action=_HelpAction, help='help for help if you need some help')  # add custom help

    # Create an argument group for last modified filters (conditionally required)
    subparsers = parser.add_subparsers(dest='mode', required=True)

    mod_group = subparsers.add_parser('mod', help='Filters for the time range of CVE data by lastModStartDate & lastModEndDate')
    all_time = subparsers.add_parser('pub', help='Filters for the time range of CVE data by pubStartDate & pubEndDate')

    # Add arguments to the group
    # mod_group.
    mod_group.add_argument("--earliest", help="Earliest date for last modified filter", metavar="YYYY-MM-DDThh:mm:ss", type=valid_date, required=True)
    mod_group.add_argument("--latest", help="Latest date for last modified filter", metavar="YYYY-MM-DDThh:mm:ss", type=valid_date, required=True)

    all_time.add_argument("--earliest", help=f"Earliest date for pubDate filter, default: {PUB_START_DATE.isoformat()}", metavar="YYYY-MM-DDThh:mm:ss", type=valid_date, default=PUB_START_DATE)
    all_time.add_argument("--latest", help=f"Latest date for pubDate filter, default: {yesterday().isoformat()}", metavar="YYYY-MM-DDThh:mm:ss", type=valid_date, default=yesterday())

    for p in subparsers.choices.values():
        p.add_argument("--file_time_range", help="Time range for file processing (e.g., 1m)", default="1m", type=parse_time_range)
    # parser.add_argument("--all_time", action='store_true', help="If set, ignores last modified filters")
    
    args = parser.parse_args()


    if args.latest < args.earliest:
        raise argparse.ArgumentError(mod_group, "--latest must not be earlier than --earliest")

    return args

def get_time_ranges(timerange_arg, earliest: dt, latest: dt) -> list[tuple[dt, dt]]:
    ONEDAY = timedelta(days=1)
    ONESEC = timedelta(seconds=1)
    match = re.match(r'(\d+)(\w+)', timerange_arg)
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
    
    logging.info(f"Dates from {earliest.isoformat()} to {latest.isoformat()} splitted into {len(output)} timeranges of {timerange_arg}")
    return output


def run():
    args = parse_args()
    check_online_status()

    celery_process = start_celery("cve2stix.celery")
    check_online_status()

    PARENT_PATH = Path("./output").absolute()
    OBJECTS_PARENT = PARENT_PATH / "objects"
    BUNDLE_PATH = PARENT_PATH / "bundles"

    filter_mode = FilterMode.MOD_DATE
    if args.mode == 'pub':
        filter_mode = FilterMode.PUB_DATE
        args.earliest = args.earliest or PUB_START_DATE
        args.latest = args.latest or yesterday()

    for time_unit, start_date, end_date in tqdm(get_time_ranges(args.file_time_range, args.earliest, args.latest)):
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
                nvd_api_key=os.getenv("NVD_API_KEY"),
                filter_mode=filter_mode,
            ),
        )
    
    celery_process.kill()

def yesterday():
    return (dt.now(timezone.utc) - timedelta(days=1)).replace(hour=23, minute=59, second=59, microsecond=0)

if __name__ == "__main__":
    run()