from dataclasses import dataclass
from datetime import datetime, date, timezone
import io
import logging
import requests
import gzip
import csv

logging.basicConfig(level=logging.INFO)

@dataclass
class EPSS:
    cve: str = ""
    date: str = None
    score: float = 0
    percentile: float = 0

class EPSSManager:
    _epss_data: dict[date, dict[str, EPSS]] = {}
    keep_old_data = False

    @classmethod
    def data(cls):
        if not cls._epss_data:
            cls.get_epss_data(datetime.now(timezone.utc))
        return cls._epss_data
    
    @classmethod
    def get_epss_data(cls, d: date):
        print(f"{cls._epss_data.keys()=}")
        if isinstance(d, datetime):
            d = d.date()
        if d in cls._epss_data:
            return cls._epss_data[d]
        d_str = d.strftime('%Y-%m-%d')
        url = "https://epss.cyentia.com/epss_scores-{}.csv.gz".format(d_str)
        resp = requests.get(url)
        csv_data = gzip.decompress(resp.content).decode()
        if not cls.keep_old_data:
            cls._epss_data = {}
        cls._epss_data[d] = dict(cls.parse_csv(csv_data, d_str))
        logging.info(f"Got {len(cls._epss_data[d])} EPSS data for {d_str}")

        return cls._epss_data[d]
        
    @staticmethod
    def parse_csv(csv_data, date_str):
        data = csv.DictReader(io.StringIO(csv_data), ["cve","epss","percentile"])
        for d in data:
            d.update(date=date_str)
            yield d['cve'], d

    @classmethod
    def get_data_for_cve(cls, cve, date=None):
        if not date:
            date = datetime.now(timezone.utc)
        data = cls.get_epss_data(date)
        return data.get(cve)