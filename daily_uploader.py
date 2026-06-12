import base64
from datetime import datetime, timedelta, timezone
import io
import os
from pathlib import Path
import traceback
import boto3
from cve2stix.celery import start_celery
from cve2stix.main import main as download_bundle
import logging


summary_file = open(os.getenv('GITHUB_STEP_SUMMARY', '/tmp/github_step_summary.md'), 'a')
print(f"### Create CVE bundle\n", file=summary_file)

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

if os.getenv('DAY_TO_PROCESS'):
    day_to_process = datetime.fromisoformat(os.getenv('DAY_TO_PROCESS'))
else:
    day_to_process = yesterday

print(f"- {day_to_process.date().isoformat()}", file=summary_file)
print(f"- {day_to_process.strftime('%a %B %-d, %Y')}", file=summary_file)

dstr = day_to_process.strftime('%Y_%m_%d')
s3_path = f"{day_to_process.strftime('%Y-%m')}/cve-bundle-{dstr}-00_00_00-{dstr}-23_59_59.json"
output_filename = Path("stix2_objects/cve-bundle.json")

logging.info("downloading bundle for %s", dstr.replace('_', '-'))
try:
    download_bundle(day_to_process.strftime("%Y-%m-%dT00:00:00"), day_to_process.strftime("%Y-%m-%dT23:59:59"))
    logging.info("finished downloading bundle for %s", dstr.replace('_', '-'))
except Exception as e:
    print(f"<details><summary>", file=summary_file)
    print(f"<h4>❌ Error Downloading Bundle: {e}</h4>", file=summary_file)
    print(f"</summary>\n<pre><code>", file=summary_file,end='')
    traceback.print_exc(file=summary_file)
    print("</code></pre>\n</details>", file=summary_file)
    raise
print("::endgroup::")

missing_file = False
if not output_filename.exists():
    missing_file = True
    logging.info("no files created, creating empty bundle...")
    output_filename.write_text("{}")


print("::group::Upload bundle to s3")
upload_file_to_s3(str(output_filename), s3_path)
exit_code = 0
logging.info("bundle uploaded to `%s`", s3_path)

if missing_file:
    print(f"❌ Empty bundle uploaded to {s3_path}", file=summary_file)
    exit_code = 19
else:
    print(f"✅ Bundle uploaded to {s3_path}", file=summary_file)

celery_process.kill()
print("::endgroup::")

exit(exit_code)

