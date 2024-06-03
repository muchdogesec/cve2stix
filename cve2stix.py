import os
import argparse
from cve2stix.main import main, Config, fetch_url
parser = argparse.ArgumentParser()


def run():
    main()


if __name__ == "__main__":
    run()
    # fetch_url("https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId=CVE-2009-0579", Config(results_per_page=3), print)