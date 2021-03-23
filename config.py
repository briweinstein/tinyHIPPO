import json
import os
import logging
from typing import List
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO,
                    filemode='a',
                    format='%(asctime)s %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    filename='/etc/tinyHIPPO/tinyHIPPO_error.log')

@dataclass(frozen=True)
class ConfigEmail:
    smtp_server: str
    email_account: str
    email_password: str
    recipient_emails: List[str]


class Config:
    def __init__(self):
        config_path = os.getenv("IOT_IDS_CONFIGPATH", "config.json")
        with open(config_path) as f:
            config_json = json.load(f)
        self.email = ConfigEmail(**config_json["email"])
        self.mac_addrs = config_json["mac_addrs"]
        self.alert_collection_path = config_json["alert_collection_path"]
        self.virustotal_api_key = config_json["virustotal_api_key"]
        self.log_event = logging.getLogger()
        
        smtp_server = config_json['email']['smtp_server']
        email_account = config_json['email']['email_account']
        email_key = config_json['email']['email_password']
        recipient_email = config_json['email']['recipient_emails']

        if smtp_server == "smtp.example.com":
            self.log_event.info('STMP Server not configured\n')
        if email_account == "openwrt@example.com":
            self.log_event.info('EMAIL ACCOUNT NOT CONFIGURED\n')
        if email_key == "super_secure_password":
            self.log_event.info('Email account password not set\n')
        if recipient_email[0] == "homeowner@example.com":
            self.log_event.info('Recipient email not configured\n')
            
