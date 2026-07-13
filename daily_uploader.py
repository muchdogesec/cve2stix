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
s3_prefix = f"{day_to_process.strftime('%Y-%m')}/cve-bundle-{dstr}-00_00_00-{dstr}-23_59_59"

logging.info("downloading bundle for %s", dstr.replace('_', '-'))
try:
    result = download_bundle(day_to_process.strftime("%Y-%m-%dT00:00:00"), day_to_process.strftime("%Y-%m-%dT23:59:59"))
    logging.info("finished downloading bundle for %s", dstr.replace('_', '-'))
except Exception as e:
    print(f"<details><summary>", file=summary_file)
    print(f"<h4>❌ Error Downloading Bundle: {e}</h4>", file=summary_file)
    print(f"</summary>\n<pre><code>", file=summary_file,end='')
    traceback.print_exc(file=summary_file)
    print("</code></pre>\n</details>", file=summary_file)
    raise
print("::endgroup::")


print("::group::Upload bundle to s3")
exit_code = 0

# Every range is written as a directory holding meta.json plus one or more
# bundle-*.json files. Upload the whole directory under the range's prefix.
output_dir = Path(result["path"])
uploaded = []
for file in sorted(output_dir.iterdir()):
    dest = f"{s3_prefix}/{file.name}"
    upload_file_to_s3(str(file), dest)
    uploaded.append(dest)
logging.info("uploaded %d files to %s/", len(uploaded), s3_prefix)

if result["total_objects"] == 0:
    print(f"❌ Empty range (meta only) uploaded to {s3_prefix}/", file=summary_file)
    exit_code = 19
else:
    print(f"✅ {len(result['bundles'])} bundles uploaded to {s3_prefix}/", file=summary_file)

celery_process.kill()
print("::endgroup::")

exit(exit_code)

