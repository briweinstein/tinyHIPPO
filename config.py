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
        with open('/etc/tinyHIPPO/cids-startuo.log', 'a+') as logging_file:
            smtp_server = config_json['email']['smtp_server']
            email_account = config_json['email']['email_account']
            email_key = config_json['email']['email_password']
            recipient_email = config_json['email']['recipient_email']

            if smtp_server == "smtp.example.com":
                logging_file.write('STMP Server not configured\n')

            if email_account == "openwrt@example.com":
                logging_file.write('EMAIL ACCOUNT NOT CONFIGURED\n')

            if email_key == "super_secure_password":
                logging_file.write('Email account password not set\n')

            if recipient_email == "homeowner@example.com":
                logging_file.write('Recipient email not configured\n')
