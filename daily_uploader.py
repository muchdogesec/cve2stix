import base64
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import boto3
from cve2stix.celery import start_celery
from cve2stix.main import main as download_bundle
import logging


summary_file = open(os.getenv('GITHUB_STEP_SUMMARY', '/tmp/nothing'), 'a')
print(f"### Create CVE bundle", file=summary_file)

def upload_file_to_s3(filepath, s3_path):
    logging.info("uploading to %s", s3_path)
    client = boto3.client('s3', endpoint_url=os.getenv('S3_ENDPOINT_URL'))
    with open(filepath, 'rb') as f:
        client.upload_fileobj(f, os.getenv('S3_BUCKET_NAME') or "cti-public", s3_path)

print("::group::Start Celery")
celery_process = start_celery("cve2stix.celery")
print("::endgroup::")

print("::group::Download Bundle from NVD")
yesterday = datetime.now(timezone.utc) - timedelta(days=1)

print(f"- {yesterday.date().isoformat()}", file=summary_file)
print(f"- {yesterday.strftime('%a %B %-d, %Y')}", file=summary_file)

dstr = yesterday.strftime('%Y_%m_%d')
s3_path = f"{yesterday.strftime('%Y-%m')}/cve-bundle-{dstr}-00_00_00-{dstr}-23_59_59.json"
output_filename = "stix2_objects/cve-bundle.json"

logging.info("downloading bundle for %s", dstr.replace('_', '-'))
download_bundle(yesterday.strftime("%Y-%m-%dT00:00:00"), yesterday.strftime("%Y-%m-%dT23:59:59"))
print("::endgroup::")

if not Path(output_filename).exists():
    logging.info("output file not created")
    print(f"❌ No bundle created", file=summary_file)
    exit(19)


print("::group::Upload bundle to s3")
logging.info("finished downloading bundle for %s", dstr.replace('_', '-'))
upload_file_to_s3(output_filename, s3_path)
logging.info("bundle uploaded to `%s`", s3_path)

print(f"✅ Bundle uploaded to {s3_path}", file=summary_file)

celery_process.kill()
print("::endgroup::")
