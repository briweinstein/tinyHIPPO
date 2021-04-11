#! /usr/bin/env python3
import re
from src.privacy_analysis.packet_analysis.packet_privacy import PacketPrivacy
from scapy.layers.inet import TCP, UDP
from scapy.all import Packet
from src.dashboard.alerts.alert import Alert, ALERT_TYPE, SEVERITY

# This list is less comprehensive than the nmap scanning list due to the variability of IoT device protocol
# implementations. The nmap scanning list will alert on a more strict list of open ports, and here will alert on the
# most suspicious ports that may be open for any device.
suspicious_ports = [21, 22, 23, 2323, 25, 110, 111, 135]

# A list of suspicious strings to search for in plaintext
suspicious_strings = ["password", "passwd", "email", "e-mail", "username", "usrname", "api_token"]


class PacketPrivacyPort(PacketPrivacy):
    def __call__(self, packet_input: Packet):
        self.packet = packet_input
        is_TCP = self.packet.haslayer(TCP)
        is_UDP = self.packet.haslayer(UDP)

        # Perform TCP and UDP checks
        if is_TCP or is_UDP:
            proto_type = TCP if is_TCP else UDP

            # Scan for using port 80 and the plaintext for privacy leaks
            if (self.packet[proto_type].dport == 80) or (self.packet[proto_type].sport == 80):
                alert_port_80 = Alert(None, "Sending data over unencrypted port.", ALERT_TYPE.PRIVACY, SEVERITY.ALERT)
                alert_port_80.alert()
                self.__scan_plaintext(proto_type)

            # Monitor suspicious ports
            if self.packet[proto_type].dport in suspicious_ports:
                alert_suspicious_ports = Alert(None, "Suspicious destination port used: " +
                                               str(self.packet[proto_type].dport), ALERT_TYPE.PRIVACY, SEVERITY.WARN)
                alert_suspicious_ports.alert()

    # Scan the plaintext for privacy leaks
    def __scan_plaintext(self, proto_type):
        # Try to get the payload
        try:
            self.payload = str(self.packet[proto_type].payload)
        except:
            return

        # TODO: There is a huge chance for false positives with credit cards and SSNs, because they're just numbers
        # TODO: Should we include them?
        # Use a regex to look for credit cards, needs a non-number before and after the numbers
        self.__regex_alert("[\D](?:[0-9]{4}-){3}[0-9]{4}[\D]|[\D][0-9]{16}[\D]", "Credit card information found in a plaintext packet.")

        # Use a regex to look for SSNs, needs a non-number before and after the numbers
        self.__regex_alert("[\D][0-9]{9}[\D]|[\D][0-9]{3}-[0-9]{2}-[0-9]{4}[\D]", "SSN information found in a plaintext packet.")

        # Use a regex to look for emails - this is not a huge privacy leak, but still mentionable
        # The email will not be included in the alert for privacy reasons
        self.__regex_alert("[^@]+@[^@]+\.[^@]+", "Email information found in a plaintext packet.")

        # Search for specific words to alert on
        for keyword in suspicious_strings:
            if keyword in self.payload:
                alert_keyword = Alert(None, f'Suspicious keyword found in a plaintext packet: {keyword}',
                                      ALERT_TYPE.PRIVACY, SEVERITY.ALERT)
                alert_keyword.alert()

    # Scan the plaintext for privacy leaks
    def __regex_alert(self, regex_string, alert_string):
        if re.search(regex_string, self.payload):
            alert_search_email = Alert(None, alert_string, ALERT_TYPE.PRIVACY, SEVERITY.ALERT)
            alert_search_email.alert()

# Sources
# https://stackoverflow.com/questions/46079770/validate-card-numbers-using-regex-python
# https://stackoverflow.com/questions/48776006/regex-to-match-ssn-in-python
# https://stackoverflow.com/questions/8022530/how-to-check-for-valid-email-address
