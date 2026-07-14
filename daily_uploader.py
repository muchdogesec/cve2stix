import os
import traceback
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone
import argparse

import boto3

from cve2stix.celery import start_celery
from cve2stix.config import FilterMode, Config
from cve2stix.main import main as download_bundle


summary_file = open(
    os.getenv("GITHUB_STEP_SUMMARY", "/tmp/github_step_summary.md"), "a"
)

print("", file=summary_file)
print("------------------------------\n", file=summary_file)
print("### Create CVE bundle\n", file=summary_file)

boto_client = boto3.client(
    "s3",
    endpoint_url=os.getenv("S3_ENDPOINT_URL"),
)
bucket_name = os.getenv("S3_BUCKET_NAME") or "cti-public"

summary_file.write(f"- S3 Bucket: {bucket_name}\n")
summary_file.write(f"- S3 Endpoint: {os.getenv('S3_ENDPOINT_URL')}\n")


def upload_file_to_s3(filepath, s3_path):
    logging.info("uploading to %s", s3_path)
    with open(filepath, "rb") as f:
        boto_client.upload_fileobj(f, bucket_name, s3_path)


def clean_prefix(prefix):
    paginator = boto_client.get_paginator("list_objects_v2")

    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
        contents = page.get("Contents", [])
        if not contents:
            continue

        # Delete in batches of up to 1000
        for i in range(0, len(contents), 1000):
            boto_client.delete_objects(
                Bucket=bucket_name,
                Delete={
                    "Objects": [
                        {"Key": obj["Key"]}
                        for obj in contents[i:i + 1000]
                    ]
                },
            )


def upload(directory, s3_prefix, result):
    print("::group::Upload bundle to s3")

    uploaded = []

    clean_prefix(s3_prefix)

    for file in sorted(Path(directory).iterdir()):
        dest = f"{s3_prefix}/{file.name}"
        upload_file_to_s3(str(file), dest)
        uploaded.append(dest)
        print(
            f"✅ uploaded `{file.name}`",
            file=summary_file,
        )

    logging.info("uploaded %d files to %s/", len(uploaded), s3_prefix)

    exit_code = 0
    if result["total_objects"] == 0:
        print(
            f"❌ Empty range (meta only) uploaded to `{s3_prefix}/`",
            file=summary_file,
        )
        exit_code = 19
    else:
        print(
            f"✅ {len(result['bundles'])} bundles uploaded to `{s3_prefix}/`",
            file=summary_file,
        )

    print("::endgroup::")
    return exit_code


def fetch():
    print("::group::Start Celery")
    celery_process = start_celery("cve2stix.celery")
    print("::endgroup::")

    print("::group::Download Bundle from NVD")

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)

    if os.getenv("DAY_TO_PROCESS"):
        day_to_process = datetime.fromisoformat(os.getenv("DAY_TO_PROCESS"))
    else:
        day_to_process = yesterday

    dstr = day_to_process.date().isoformat()

    print(f"- {dstr}", file=summary_file)
    print(
        f"- {day_to_process.strftime('%a %B %-d, %Y')}",
        file=summary_file,
    )

    s3_prefix = (
        f"v2/{day_to_process.strftime('%Y-%m')}"
        f"/cves-{day_to_process.strftime('%Y%m%d')}"
    )

    logging.info("downloading bundle for %s", dstr)

    try:
        cfg = Config(
            filename=f"cves-{day_to_process.strftime('%Y%m%d')}",
            filter_mode=FilterMode.MOD_DATE,
        )
        result = download_bundle(
            day_to_process.strftime("%Y-%m-%dT00:00:00"),
            day_to_process.strftime("%Y-%m-%dT23:59:59"),
            config=cfg,
        )
        logging.info("finished downloading bundle for %s", dstr)
    except Exception as e:
        print("<details><summary>", file=summary_file)
        print(
            f"<h4>❌ Error Downloading Bundle: {e}</h4>",
            file=summary_file,
        )
        print("</summary>\n<pre><code>", file=summary_file, end="")
        traceback.print_exc(file=summary_file)
        print("</code></pre>\n</details>", file=summary_file)
        celery_process.kill()
        raise

    print("::endgroup::")

    try:
        return upload(result["path"], s3_prefix, result)
    finally:
        celery_process.kill()


def parse_meta(dir: str):
    meta_file = Path(dir) / "meta.json"
    if not meta_file.exists():
        raise Exception(f"meta.json not found in {dir}")
    import json

    with open(meta_file, "r") as f:
        return json.load(f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch_parser = subparsers.add_parser(
        "fetch",
        help="Download CVEs from NVD and upload to S3",
    )
    fetch_parser.add_argument(
        "--day",
        help="Day to process (YYYY-MM-DD). Defaults to yesterday.",
    )

    upload_parser = subparsers.add_parser(
        "upload",
        help="Upload an existing bundle directory to S3",
    )
    upload_parser.add_argument(
        "directory",
        help="Directory containing meta.json and bundle-*.json files",
    )
    upload_parser.add_argument(
        "s3_prefix",
        help="Destination S3 prefix (e.g. v2/2026-07/cves-20260713)",
    )
    upload_parser.add_argument(
        "--total-objects",
        type=int,
        default=1,
        help="Total objects in the bundle (used to determine exit code)",
    )

    args = parser.parse_args()

    if args.command == "fetch":
        if args.day:
            os.environ["DAY_TO_PROCESS"] = args.day
        raise SystemExit(fetch())

    elif args.command == "upload":
        raise SystemExit(upload(args.directory, args.s3_prefix, parse_meta(args.directory)))