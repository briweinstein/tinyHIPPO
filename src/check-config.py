#!/usr/bin/env python3

import json

config_file = open('/etc/capstone-ids/config.json','r')
config_data = json.load(config_file)

logging_file = open('/etc/capstone-ids/cids-startuo.log','a+')

SMTP_SERVER = config_data['email']['smtp_server']
EMAIL_ACCOUNT = config_data['email']['email_account']
EMAIL_KEY = config_data['email']['email_password']
RECIPIENT_EMAIL = config_data['email']['recipient_email']

if SMTP_SERVER == "smtp.example.com":
	logging_file.write('STMP Server not configured\n')

if EMAIL_ACCOUNT == "openwrt@example.com":
	logging_file.write('EMAIL ACCOUNT NOT CONFIGURED\n')

if EMAIL_KEY == "super_secure_password":
	logging_file.write('Email account password not set\n')

if RECIPIENT_EMAIL == "homeowner@example.com":
	logging_file.write('Recipient email not configured\n')

config_file.close()
logging_file.close()
