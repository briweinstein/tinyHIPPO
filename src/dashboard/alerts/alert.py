#! /usr/bin/env python3

import json
import hashlib
from datetime import datetime
from scapy.packet import Packet
from scapy.utils import hexdump
from src.emailalerts import emailsystem
from src import run_config as CONFIG


class ALERT_TYPE:
    PRIVACY = "Privacy"
    IDS = "IDS"
    UNKNOWN = "Unknown"


class SEVERITY:
    INFO = 0
    WARN = 1
    ALERT = 2


class Alert:
    def __init__(self, alert_description="", alert_type=ALERT_TYPE.UNKNOWN, alert_severity=SEVERITY.INFO):
        """
        Parses the given information into a alert object, no packet present
        :param alert_description: A description providing context/information as to why this
                                  particular packet was flagged
        :param alert_type: IDS or PRIVACY
        :param is_destination: Boolean telling alert system if the IoT device is the dst or src
        """
        # Initialize with default values
        self.timestamp = str(datetime.now())
        self.device_name = ""
        self.device_ip = "None"
        self.device_mac = "None"
        self.type = str(alert_type)
        self.severity = int(alert_severity)

        self.description = alert_description
        hasher = hashlib.sha1()
        hasher.update(str(self.device_mac + self.timestamp).encode('utf-8'))
        self.id = int(hasher.hexdigest()[:4], 16)

        # If there is raw information, try to save it
        self.payload_info = "None"

    def __init__(self, pkt: Packet, alert_description="", alert_type=ALERT_TYPE.UNKNOWN, alert_severity=SEVERITY.INFO,
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
        self.type = str(alert_type)
        self.severity = int(alert_severity)

        if is_destination:
            if "IP" in pkt:
                self.device_ip = pkt["IP"].dst
            if "Ethernet" in pkt:
                self.device_mac = pkt["Ethernet"].dst
        else:
            if "IP" in pkt:
                self.device_ip = pkt["IP"].src
            else:
                self.device_ip = "[Layer 2]"
            if "Ethernet" in pkt:
                self.device_mac = pkt["Ethernet"].src
            else:
                self.device_mac = "[Unknown]"

        # Use some magic config trickery to get the name for this device, otherwise unknown
        if "magic":
            self.device_name = "Unknown"

        self.description = alert_description
        hasher = hashlib.sha1()
        hasher.update(str(self.device_mac + self.timestamp).encode('utf-8'))
        self.id = int(hasher.hexdigest()[:4], 16)

        # If there is raw information, try to save it
        self.payload_info = hexdump(pkt, dump=True)

    def log_alert(self):
        """
        Logs the alert object to the log file
        :return:
        """
        log_file = "unknown_error.log"
        if self.type == ALERT_TYPE.IDS:
            log_file = "ids_alerts.log"
        elif self.type == ALERT_TYPE.PRIVACY:
            log_file = "privacy_alerts.log"
        f = open(log_file, "a")
        f.write(str(self))
        f.close()

    def jsonify(self):
        """
        JSONification of the data within the object
        :return:
        """
        alert_json = {"id": self.id, "type": self.type, "device_name": self.device_name, "device_ip": self.device_ip,
                      "device_mac": self.device_mac, "timestamp": self.timestamp, "description": self.description,
                      "payload_info": self.payload_info, "severity": self.severity}

        return alert_json

    def save_alert(self):
        """
        Saves the alert object in JSON format to the collection
        :return:
        """
        path = CONFIG.alert_collection_path

        # Open alert collection file to read
        alert_data = None
        with open(path, 'r') as alert_collection:
            try:
                alert_data = json.load(alert_collection)
            except json.decoder.JSONDecodeError:
                alert_data = json.loads("{\n \"alerts\": []\n}\n")

            # Get the list of alerts, add the current object to the list
            alerts = alert_data["alerts"]
            alerts.append(self.jsonify())

        # Load object as JSON
        serialized_data = json.dumps(alert_data, indent=4)

        # Write to file
        write_alert_collection = open(path, 'w')
        write_alert_collection.write(serialized_data)
        write_alert_collection.close()

    def alert(self):
        """
        Inform the townspeople (Send the alert where it should go)
        :return:
        """
        # Send email if urgent enough
        if self.severity > 1:
            emailsystem.send_email_alert(self)

        # Log the alert to the log file
        self.log_alert()

        # Save the alert in the JSON collection for frontend use
        self.save_alert()

    def __str__(self):
        string = "*******************************************************\n"
        string += "{0} Alert (ID: {1})\n".format(str(self.type), str(self.id))
        string += "{0}\n".format(str(self.description))
        string += "-------------------------------------------------------\n"
        string += "Time of alert: {0}\n".format(str(self.timestamp))
        string += "Affected Device: {0}\n".format(str(self.device_name))
        string += "MAC: {0}\n".format(str(self.device_mac).upper())
        string += "IP: {0}\n".format(str(self.device_ip))
        string += "-------------------------------------------------------\n"
        string += "Additional info (Packet Dump): \n{0}\n".format(self.payload_info)
        string += "*******************************************************\n"
        return string
