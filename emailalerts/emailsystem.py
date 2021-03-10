#! /usr/bin/env python3

import ssl
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dashboard.alerts import alert

email_config_file = open('/etc/capstone-ids/config.json', 'r')
email_config_data = json.load(email_config_file)

SMTP_SERVER = email_config_data['email']['smtp_server']
EMAIL_ACCOUNT = email_config_data['email']['email_account']
EMAIL_KEY = email_config_data['email']['email_password']
RECIPIENT_EMAIL = email_config_data['email']['recipient_email']
PORT = 587  # For starttls

# Create a secure SSL context
context = ssl.create_default_context()


def send_message(msg):
    """
    This function will send the given message to the appropriate recipient
    :param msg: (String) message to be sent
    :return: None
    """
    try:
        server = smtplib.SMTP(SMTP_SERVER, PORT)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(EMAIL_ACCOUNT, EMAIL_KEY)
        message = MIMEMultipart("alternative")
        message["Subject"] = "Capstone IDS - OpenWrt Email Alert"
        message["From"] = 'OpenWrt Alerting System'
        message["To"] = RECIPIENT_EMAIL
        part1 = MIMEText(msg, 'plain')
        part2 = MIMEText(msg, 'html')
        message.attach(part1)
        message.attach(part2)
        server.sendmail(EMAIL_ACCOUNT, RECIPIENT_EMAIL, message.as_string())
        server.quit()
        print('Email was sent successfully')
    except Exception as e:
        print('Could not send email message to specified recipient.')
        print(e)

def send_email_alert(alert_object: alert):
    """
    Overloaded function for alert object as parameter
    :param alert_object: Alert object
    :return:
    """
    send_email_alert(alert_object.type, alert_object.device_name, alert_object.device_ip,
                     alert_object.device_mac, alert_object.timestamp, alert_object.info)

def send_email_alert(alert_type, device_name, device_ip, device_mac, timestamp, info):
    """
    This function will construct a proper HTML message with the appropriate information such as alert type, device name
    IP address, MAC address, etc.
    :param alert_type: One of 'Security' or 'Privacy'
    :param device_name: Name of the device, i.e. 'Robot Camera'
    :param device_ip: IP address of the device, i.e. '10.1.2.3'
    :param device_mac: MAC address of the device, i.e. 'AA:BB:CC:DD:EE:FF'
    :param timestamp: Timestamp of when the alert occurs
    :param info: Any additional information related to the alert
    :return:
    """
    msg = """\
    <html>
    <head>
        <style type="text/css">
        </style>
    </head>
    <body>
        <table class='alert' style="border:3px solid #FF7D7D;border-collapse:collapse;font-family:Verdana;font-size:10pt;">
            <tr>
                <th colspan="2" style="border-bottom:3px solid #FF7D7D;padding:5px;background-color:#FFE0E0">Security & Privacy Alert</th>
            </tr>
            <tr>
                <td>Alert: </td>
                <td>{0}</td>
            </tr>
            <tr>
            </tr>
            <tr>
                <td style="background-color:#FFE0E0;text-align:justify;padding:3px">Status: </td>
                <td style="background-color:#FFE0E0;text-align:justify;padding:3px">Vulnerable</td>
            </tr>
            <tr>
                <td>Device Name</td>
                <td>{1}</td>
            </tr>
            <tr class='alt'>
                <td style="background-color:#FFE0E0;text-align:justify;padding:3px">Device IP Address</td>
                <td style="background-color:#FFE0E0;text-align:justify;padding:3px">{2}</td>
            </tr>
            <tr>
                <td>Device MAC Address</td>
                <td>{3}</td>
            </tr>
            <tr>
                <td style="background-color:#FFE0E0;text-align:justify;padding:3px">Time of Alert</td>
                <td style="background-color:#FFE0E0;text-align:justify;padding:3px">{4}</td>
            </tr>
            <tr>
                <td>Alert info</td>
                <td>{5}</td>
            </tr>
        </table>
    </body>
    </html>
    """
    formatted_msg = msg.format(str(alert_type), str(device_name), str(device_ip), str(device_mac), str(timestamp),
                               str(info))
    send_message(formatted_msg)