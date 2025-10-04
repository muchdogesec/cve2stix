import logging
from celery import Celery
from .stix_store import store_cve_in_bundle
from stix2.datastore.filters import Filter
from .config import Config

import logging
import subprocess
import sys
import time
from cve2stix.config import Config
import logging
import subprocess
import sys
import time
import os
import atexit


app = Celery("cve2stix", broker=Config.REDIS_URL, backend=Config.REDIS_URL)
app.conf.task_default_queue = "default"
app.conf.worker_concurrency = 8  # Set the number of worker processes
app.conf.worker_log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
app.conf.worker_log_file = "logs/celery.log"  # Specify the log file path
app.autodiscover_tasks()


@app.task()
def cve_syncing_task(start, end, config):
    from .main import fetch_data

    config = Config(**config)
    fetch_data(start, end, config)


@app.task()
def preparing_results(task_results, config, filename=None):
    from .main import map_default_objects, map_extensions

    config = Config(**config)
    results = []
    results = map_default_objects(config, results)
    results = map_extensions(config, results)

    vulnerabilities = config.fs.query([Filter("type", "=", "vulnerability")])
    if vulnerabilities:
        all_objects = config.fs.query([Filter("type", "!=", "")])
        store_cve_in_bundle(config.stix2_bundles_folder, all_objects, filename)
    else:
        logging.info("Not writing any file because no output")


def check_online_status(app: Celery = app):
    availability_status = app.control.inspect().ping()
    logging.info("celery workers ping: %s", str(availability_status))
    return availability_status


def start_celery(path: str, cwd=".", app=app):
    logging.info(f"Starting celery: {path}")
    args = [
        "celery",
        "-A",
        path,
        "--workdir",
        cwd,
        "worker",
        "--loglevel",
        "info",
        "--purge",
    ]
    p = subprocess.Popen(args, stdout=sys.stdout, stderr=sys.stderr)

    logging.info(f"Waiting 10 seconds for celery to initialize")
    for i in range(10):
        availability_status = check_online_status(app)
        if availability_status:
            break
        time.sleep(1)
    if not availability_status:
        p.kill()
        raise Exception("Unable to start worker")
    logging.info("Worker started")
    atexit.register(p.kill)
    return p
