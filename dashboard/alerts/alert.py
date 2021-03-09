#! /usr/bin/env python3

import json
import datetime
from scapy.all import *
from emailalerts import emailsystem

class ALERT_TYPE:
    PRIVACY = "Privacy"
    IDS = "IDS"
    UNKNOWN = "Unknown"

class SEVERITY:
    INFO = 0
    WARN = 1
    ALERT = 2

class alert:
    def __init__(self):
        """
        Default constructor for the alert object
        """
        # Alert type (Privacy (P) vs IDS (I))
        self.type = str(ALERT_TYPE.UNKNOWN)

        # Device specific information
        self.device_name = ""
        self.device_ip = ""
        self.device_mac = ""

        # Additional info
        self.timestamp = datetime.datetime
        self.description = ""
        self.payload_info = b''
        self.severity = SEVERITY.INFO

        # Unique Identifier (For easily finding alerts in logs)
        self.id = 0

    def __init__(self, pkt: packet, alert_description: str, alert_type: ALERT_TYPE, severity: SEVERITY, is_destination =False):
        """
        Parses the given packet and extra information into a alert object
        :param pkt: Scapy's packet object, the collected info from the alert
        :param alert_description: A description providing context/information as to why this
                                  particular packet was flagged
        :param alert_type: IDS or PRIVACY
        :param is_destination: Boolean telling alert system if the IoT device is the dst or src
        """
        # Initialize with default values
        self.__init__()
        self.type = str(alert_type)
        self.severity = int(severity)

        if is_destination:
            if "IP" in pkt:
                self.device_ip = pkt["IP"].dst
            if "Ethernet" in pkt:
                self.device_mac = pkt["Ethernet"].dst
        else:
            if "IP" in pkt:
                self.device_ip = pkt["IP"].src
            if "Ethernet" in pkt:
                self.device_mac = pkt["Ethernet"].src

        # Use some magic config trickery to get the name for this device, otherwise unknown
        if "magic":
            self.device_name = "Unknown"

        self.description = alert_description
        self.id = hash(self.device_mac + str(self.timestamp))

        # If there is raw information, try to save it
        if "Raw" in pkt:
            self.payload_info = pkt["Raw"].load

    def logAlert(self):
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

    def saveAlert(self):
        """
        Saves the alert object in JSON format to the collection
        :return:
        """
        try:
            # Open config file to get path
            config_file = open('/etc/capstone-ids/config.json', 'r')
            config_data = json.load(config_file)
            path = config_data["alert_collection_path"]

            # Default path
            if path == "" or path is None:
                path = "/etc/capstone-ids/alert_collection.json"

            # Open alert collection file to read
            alert_collection = open(path, 'r')
            alert_data = json.load(alert_collection)

            # Get the list of alerts, add the current object to the list
            alerts = alert_data["alerts"]
            alerts.append(self.jsonify())

            #Close/Open the file to RW properly (In case of earlier error, doesn't terminate the file's contents
            alert_collection.close()
            write_alert_collection = open(path, 'w')
            write_alert_collection.write(json.dumps(alert_data))
            write_alert_collection.close()
        except Exception as e:
            print("Failed to save alert, reason: " + str(e))

    def alert(self):
        """
        Inform the townspeople (Send the alert where it should go)
        :return:
        """
        # Send email if urgent enough
        if self.severity > 1:
            emailsystem.send_email_alert(self)

        # Log the alert to the log file
        self.logAlert()

        # Save the alert in the JSON collection for frontend use
        self.saveAlert()

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
        string += "Additional info (Packet Dump): \n{:X}\n".format(self.payload_info)
        string += "*******************************************************\n"
