#! /usr/bin/env python3

import datetime
import smtplib
import ssl
from creds import EMAIL_KEY
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

smtp_server = "smtp.gmail.com"
port = 587  # For starttls
# TODO: change this to a real email account that we use
sender_email = "openwrt@example.com"

# TODO: change this to the email that should receive the alerts
recipient_email = 'test@example.com'

# TODO: move the emails and or their creds to a config file for the OpenWrt package

# Create a secure SSL context
context = ssl.create_default_context()


def send_message(subj, msg):
    """
    This function will send the given message to the appropriate recipient
    :param subj: (String) Subject of the email, usually in the format of "OpenWrt Alert - XXX"
    :param msg: (String) message to be sent
    :return: None
    """
    try:
        server = smtplib.SMTP(smtp_server, port)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(sender_email, EMAIL_KEY)
        message = MIMEMultipart("alternative")
        message["Subject"] = "Test OpenWrt Email Alert"
        message["From"] = 'OpenWrt Alerting System'
        message["To"] = recipient_email
        part1 = MIMEText(msg, 'plain')
        part2 = MIMEText(msg, 'html')
        message.attach(part1)
        message.attach(part2)
        server.sendmail(sender_email, recipient_email, message.as_string())
        server.quit
        print('Email was sent successfully')
    except Exception as e:
        print('Could not send email message to specified recipient.')
        print(e)
        

# TODO: add functionality to allow custom info, such as date, IP address, etc.
def send_email_alert():
    """
    This function will send an email to notify the user about a privacy or security Vulnerability
    :return: None
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
                <td>Security (or Privacy)</td>
            </tr>
            <tr>
            </tr>
            <tr>
                <td style="background-color:#FFE0E0;text-align:justify;padding:3px">Status: </td>
                <td style="background-color:#FFE0E0;text-align:justify;padding:3px">Vulnerable</td>
            </tr>
            <tr>
                <td>IP Address</td>
                <td>192.168.1.100</td>
            </tr>
            <tr class='alt'>
                <td style="background-color:#FFE0E0;text-align:justify;padding:3px">Device Name</td>
                <td style="background-color:#FFE0E0;text-align:justify;padding:3px">IoT Device #1</td>
            </tr>
            <tr>
                <td>Time of Alert</td>
                <td>Feb 10, 2021, 13:52:45GMT</td>
            </tr>
        </table>
    </body>
    </html>
    """
    send_message("Test OpenWrt Email Alert", msg)
    

# Uncomment if you want to run this file as a standalone script
# send_email_alert()
