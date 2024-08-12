import logging, os
from celery import Celery
from celery.signals import setup_logging  # noqa
from .stix_store import StixStore
from .config import Config
from .helper import delete_subfolders, append_data


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


@app.task()
def preparing_results(task_results, config, filename=None):
    from .main import map_marking_definition, map_identity
    config = Config(**config)
    results = []
    results = map_marking_definition(config, results)
    results = map_identity(config, results)
    results = append_data(results, config.file_system)

    stix_store = StixStore(
        config.stix2_objects_folder, config.stix2_bundles_folder
    )
    stix_store.store_cve_in_bundle(results, filename, update=True)
    if bool(os.getenv("CENTRAL_CELERY")):
        delete_subfolders(config.stix2_objects_folder)


