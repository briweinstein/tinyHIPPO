import json
import os
from typing import List

from dataclasses import dataclass

@dataclass(frozen=True)
class ConfigEmail:
    smtp_server: str
    email_account: str
    email_password: str
    recipient_emails: List[str]


class Config:
    def __init__(self):
        config_path = os.getenv("IOT_IDS_CONFIGPATH", "src/config.json")
        with open(config_path) as f:
            config_json = json.load(f)
        self.email = ConfigEmail(**config_json["email"])
        self.mac_addrs = config_json["mac_addrs"]
        self.alert_collection_path = config_json["alert_collection_path"]

CONFIG = Config()
