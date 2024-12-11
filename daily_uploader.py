import base64
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import boto3
from cve2stix.main import main as download_bundle
import logging


def upload_file_to_s3(filepath, s3_path):
    logging.info("uploading to %s", s3_path)
    client = boto3.client('s3', endpoint_url=os.getenv('S3_ENDPOINT_URL'))
    with open(filepath, 'rb') as f:
        client.upload_fileobj(f, os.getenv('S3_BUCKET_NAME') or "cti-public", s3_path)


yesterday = datetime.now(timezone.utc) - timedelta(days=1)
dstr = yesterday.strftime('%Y_%m_%d')
s3_path = f"cve2stix-github-action-output/{yesterday.strftime('%Y-%m')}/cve-bundle-{dstr}-00_00_00-{dstr}-23_59_59.json"

logging.info("downloading bundle for %s", dstr.replace('_', '-'))
download_bundle(yesterday.strftime("%Y-%m-%dT00:00:00"), yesterday.strftime("%Y-%m-%dT23:59:59"))


logging.info("finished downloading bundle for %s", dstr.replace('_', '-'))
upload_file_to_s3('stix2_objects/cve-bundle.json', s3_path)
logging.info("bundle uploaded to `%s`", s3_path)
