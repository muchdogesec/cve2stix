from datetime import datetime, timezone

import pytest
from cve2stix.config import Config


@pytest.fixture
def config(tmp_path):
    return Config(
        start_date=datetime(2025, 7, 1, tzinfo=timezone.utc),
        end_date=datetime(2025, 7, 10, tzinfo=timezone.utc),
        file_system=str(tmp_path),
        stix2_objects_folder=str(tmp_path / "objects"),
        stix2_bundles_folder=str(tmp_path / "bundles"),
    )

@pytest.fixture(autouse=True, scope="module")
def celery_eager():
    from cve2stix.celery import app

    app.conf.task_always_eager = True
    app.conf.broker_url = None
    yield
    app.conf.task_always_eager = False