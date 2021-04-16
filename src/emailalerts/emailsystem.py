import ssl
import smtplib
from typing import TYPE_CHECKING
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src import db
from src.database.models import EmailInformation

if TYPE_CHECKING:
    from src.dashboard.alerts.alert import Alert

PORT = 587  # For starttls

# Create a secure SSL context
context = ssl.create_default_context()


def send_message(msg: str):
    """
    This function will send the given message to the appropriate recipient
    :param msg: (String) message to be sent
    :return: None
    """
    email_config = db.session.query(EmailInformation).first()
    try:
        server = smtplib.SMTP(email_config.smtp_server, PORT)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(email_config.sender_address, email_config.sender_email_password)
        message = MIMEMultipart("alternative")
        message["Subject"] = "Tiny HIPPO IDS - OpenWrt Email Alert"
        message["From"] = 'OpenWrt Alerting System'
        message["To"] = email_config.recipient_addresses
        part1 = MIMEText(msg, 'plain')
        part2 = MIMEText(msg, 'html')
        message.attach(part1)
        message.attach(part2)
        server.sendmail(email_config.sender_address, email_config.recpient_addresses, message.as_string())
        server.quit()
        print('Email was sent successfully')
    except Exception as e:
        print('Could not send email message to specified recipient.')
        print(e)


def send_email_alert(alert_object: 'Alert'):
    """
    This function will construct a proper HTML message with the appropriate information such as alert type, device name
    IP address, MAC address, etc.
    :param alert_object: Alert object
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
    formatted_msg = msg.format(str(alert_object.type), str(alert_object.device_name), str(alert_object.device_ip),
                               str(alert_object.device_mac), str(alert_object.timestamp),
                               str(alert_object.description))
    send_message(formatted_msg)
