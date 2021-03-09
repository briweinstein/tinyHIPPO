#! /usr/bin/env python3
import datetime
from scapy.all import *
from privacy_analysis import *
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

    def saveAlert(self):
        """
        Saves the alert object to the log file
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
        print("Alert was saved to file: " + log_file)

    def alert(self):
        """
        Inform the townspeople (Send the alert where it should go)
        :return:
        """
        if self.severity > 1:
            emailsystem.send_email_alert(self)
        self.saveAlert()


    def __str__(self):
        string = "*******************************************************\n"
        string += "{0} Alert (ID: {1})\n".format(str(self.type), str(self.id))
        string += "{0}\n".format(str(self.description))
        string = "-------------------------------------------------------\n"
        string += "Time of alert: {0}\n".format(str(self.timestamp))
        string += "Affected Device: {0}\n".format(str(self.device_name))
        string += "MAC: {0}\n".format(str(self.device_mac).upper())
        string += "IP: {0}\n".format(str(self.device_ip))
        string += "-------------------------------------------------------\n"
        string += "Additional info (Packet Dump): \n{:X}\n".format(self.payload_info)
        string += "*******************************************************\n"
