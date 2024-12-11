from datetime import datetime, timedelta
import os
import boto3
from dotenv import load_dotenv
from pytz import timezone
from cve2stix.main import main as download_bundle
import logging


def upload_file_to_s3(filepath, s3_path):
    logging.info("uploading to %s", s3_path)
    client = boto3.client('s3', endpoint_url=os.getenv('S3_ENDPOINT_URL'))
    with open(filepath, 'rb') as f:
        client.upload_fileobj(f, os.getenv('S3_BUCKET_NAME') or "cti-public", s3_path)



yesterday = datetime.now(timezone('UTC')) - timedelta(days=1)
dstr = yesterday.strftime('%Y-%m-%d')
path = f"cve/{yesterday.strftime('%Y-%m')}/cve-bundle-{dstr}-00_00_00-{dstr}-23_59_59.json"
logging.info("downloading bundle for %s", dstr)
download_bundle(yesterday.strftime("%Y-%m-%dT00:00:00"), yesterday.strftime("%Y-%m-%dT23:59:59"))
logging.info("finished downloading bundle for %s", dstr)
upload_file_to_s3('stix2_objects/cve-bundle.json', path)
