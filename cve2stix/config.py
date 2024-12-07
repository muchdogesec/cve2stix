import logging
import requests
import json
import os
import redis
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from stix2 import FileSystemStore
from uuid import UUID

load_dotenv()

def load_file_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error loading JSON from {url}: {e}")
        return None

def validate_date_from_env(key):
    try:
        value = os.getenv(key)
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
        return value
    except:
        return None

@dataclass
class Config:
    type: str = "cve"
    CVE2STIX_FOLDER = Path(os.path.abspath(__file__)).parent
    REPO_FOLDER = CVE2STIX_FOLDER.parent
    LAST_MODIFIED_TIME = os.getenv('CVE_LAST_MODIFIED_EARLIEST')
    start_date:str = validate_date_from_env('CVE_LAST_MODIFIED_EARLIEST')
    end_date: str = validate_date_from_env('CVE_LAST_MODIFIED_LATEST') if os.getenv("CVE_LAST_MODIFIED_LATEST") else datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    stix2_objects_folder: str = str(os.getenv('CTI_DATA_FOLDER_CVE') if os.getenv('CTI_DATA_FOLDER_CVE') else REPO_FOLDER / "stix2_objects")
    stix2_bundles_folder: str = str(os.getenv('CTI_DATA_FOLDER_CVE') if os.getenv('CTI_DATA_FOLDER_CVE') else REPO_FOLDER / "stix2_objects")
    store_in_filestore: bool = True
    disable_parsing: bool = False
    cve_id:str = ""
    cve_cvssV3_severity:str = ""
    nvd_cve_api_endpoint: str = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    cpematch_api_endpoint: str = "https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId="
    results_per_page: int = int(os.getenv('RESULTS_PER_PAGE', 500))
    nvd_api_key: str = os.getenv('NVD_API_KEY')
    file_system: str = os.getenv('CTI_DATA_FOLDER_CVE') if os.getenv('CTI_DATA_FOLDER_CVE') else stix2_objects_folder
    if not os.path.exists(file_system):
        os.makedirs(file_system)
    namespace = UUID("562918ee-d5da-5579-b6a1-fae50cc6bad3")
    data_path = REPO_FOLDER

    CVE2STIX_IDENTITY_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/cve2stix.json"
    CVE2STIX_MARKING_DEFINITION_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/cve2stix.json"
    CVE2STIX_IDENTITY_REF = json.loads(load_file_from_url(url=CVE2STIX_IDENTITY_URL))
    CVE2STIX_MARKING_DEFINITION_REF = json.loads(load_file_from_url(url=CVE2STIX_MARKING_DEFINITION_URL))

    TLP_CLEAR_MARKING_DEFINITION_REF = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/10"

    @property
    def fs(self):
        return FileSystemStore(self.file_system)