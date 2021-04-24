import json
import os
import logging
from typing import List
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ConfigEmail:
    smtp_server: str
    email_account: str
    email_password: str
    recipient_emails: List[str]


class Config:
    def __init__(self):
        self.install_path = Path("C:\\Users\\Brianna\\PycharmProjects\\OpenWrt-IoT-IDS-Privacy")
        config_path = self._absolute_path("config.json")
        logging.basicConfig(level=logging.INFO,
                            filemode='a',
                            format='%(asctime)s %(name)s %(levelname)s %(message)s',
                            datefmt='%H:%M:%S',
                            filename=str(self._absolute_path("tinyHIPPO_error.log")))
        with open(config_path) as f:
            config_json = json.load(f)
        self.db_file = self._absolute_path("tinyHIPPO.db")
        self.virustotal_api_key = config_json["virustotal_api_key"]
        self.log_event = logging.getLogger()
        self.sniffing_interface = config_json["sniffing_interface"]

    def _absolute_path(self, relative_path: str) -> Path:
        return self.install_path / relative_path
