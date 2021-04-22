import hashlib
from time import time
from scapy.utils import raw
from datetime import datetime
from enum import Enum, IntEnum

from src import db
from src.emailalerts import emailsystem
from src.database.models import Alerts


class AlertType(Enum):
    PRIVACY = "Privacy"
    IDS = "IDS"
    ANOMALY = "Anomaly"
    UNKNOWN = "Unknown"


class Severity(IntEnum):
    INFO = 0
    WARN = 1
    ALERT = 2


class Alert:
    def __init__(self, pkt=None, alert_description="",
                 alert_type: AlertType = AlertType.UNKNOWN,
                 alert_severity: Severity = Severity.INFO,
                 is_destination=False):
        """
        Parses the given packet and extra information into a alert object
        :param pkt: Scapy's packet object, the collected info from the alert
        :param alert_description: A description providing context/information as to why this
                                  particular packet was flagged
        :param alert_type: IDS or PRIVACY
        :param is_destination: Boolean telling alert system if the IoT device is the dst or src
        """
        # Initialize with default values
        self.timestamp = str(datetime.now())
        self.device_name = ""
        self.device_ip = ""
        self.device_mac = ""
        self.type = alert_type
        self.severity = alert_severity

        try:
            if pkt:
                # Default values
                self.device_ip = "[Layer 2]"
                if is_destination:
                    if "IP" in pkt:
                        self.device_ip = pkt["IP"].dst
                    self.device_mac = pkt["Ethernet"].dst
                else:
                    if "IP" in pkt:
                        self.device_ip = pkt["IP"].src
                    self.device_mac = pkt["Ethernet"].src
                self.payload_info = raw(pkt)
            else:
                self.payload_info = "None"
        except KeyError as e:
            print("Error attempting to read from packet: " + str(e))

        # TODO: Use some magic config trickery to get the name for this device, otherwise unknown
        self.device_name = "Unknown"

        self.description = alert_description
        hasher = hashlib.sha1()
        hasher.update(str(self.device_mac + self.timestamp).encode('utf-8'))
        self.id = int(hasher.hexdigest()[:4], 16)

    def _save_alert(self):
        """
        Saves the alert to the SQLite Database
        :return: The alert object saved to the database as a model
        """
        new_alert = Alerts(alert_type=self.type.value,
                           description=self.description,
                           severity=self.severity.value,
                           timestamp=self.timestamp)
        if self.device_mac:
            new_alert.mac_address = self.device_mac
            new_alert.payload = self.payload_info

        # Decide if the alert should be committed
        commit = db.session_alert_count > 25 or time() - db.session_alert_time >= 3600

        # Adjust session commit information
        if commit:
            db.session_alert_time = time()
            db.session_alert_count = 0
        else:
            db.session_alert_count += 1

        # Alert added to session, committed in bulk depending on frequency or time
        return Alerts.insert_new_object(new_alert, commit=commit)

    def alert(self):
        """
        Determines whether to send an email for this alert and saves it to teh sqlite database
        :return: nothing
        """
        # Send email if urgent enough
        if self.severity > 1:
            # emailsystem.send_email_alert(self)
            print("You've got mail!")

        # Save the alert in the SQLite database for frontend use
        self._save_alert()
