import logging, os
from celery import Celery
from celery.signals import setup_logging  # noqa
from .stix_store import store_cve_in_bundle
from stix2.datastore.filters import Filter
from .config import Config
from .helper import append_data

import logging
import os
import subprocess
import sys
import time
from cve2stix.config import Config
import argparse
import logging
import subprocess
import sys
import calendar
import time
import os



if bool(os.getenv("CENTRAL_CELERY")):
    from config import celery_app as app

if not bool(os.getenv("CENTRAL_CELERY")):
    CELERY_RESULT_BACKEND='amqp://',
    app = Celery(
        'cve2stix', broker=Config.REDIS_URL, backend=Config.REDIS_URL
    )
    app.conf.task_default_queue = 'default'
    app.conf.worker_concurrency = 8  # Set the number of worker processes
    app.conf.worker_log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    app.conf.worker_log_file = 'logs/celery.log'  # Specify the log file path
    app.autodiscover_tasks()


@setup_logging.connect
def config_loggers(*args, **kwargs):
    from logging.config import dictConfig  # noqa
    # dictConfig({})


@app.task()
def cve_syncing_task(start, end, config):
    from .main import fetch_data
    config = Config(**config)
    fetch_data(start, end, config)

@app.task
def get_matching_criteria(start):
    pass

@app.task
def is_online():
    return True

@app.task()
def preparing_results(task_results, config, filename=None):
    from .main import map_marking_definition, map_identity, map_extensions
    config = Config(**config)
    results = []
    results = map_marking_definition(config, results)
    results = map_identity(config, results)
    results = map_extensions(config, results)
    results = append_data(results, config.file_system)

    vulnerabilities = config.fs.query([Filter("type", "=", "vulnerability")])
    if vulnerabilities:
        store_cve_in_bundle(config.stix2_bundles_folder, results, filename)
    else:
        logging.info("Not writing any file because no output")


def check_online_status(app: Celery=app):
    availability_status = app.control.inspect().ping()
    logging.info("celery workers ping: %s", str(availability_status))
    return availability_status

def start_celery(path: str, cwd=".", app=app):
    logging.info(f"Starting celery: {path}")
    args = ["celery", "-A", path, "--workdir", cwd, "worker", "--loglevel", "info", "--purge"]
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
    return p