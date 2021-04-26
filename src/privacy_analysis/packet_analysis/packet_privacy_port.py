import re

from src import run_config
from src.privacy_analysis.packet_analysis.packet_privacy import PacketPrivacy
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import Ether
from scapy.all import Packet
from src.dashboard.alerts.alert import Alert, AlertType, Severity

"""
This list is less comprehensive than the nmap scanning list due to the variability of IoT device protocol
implementations. The nmap scanning list will alert on a more strict list of open ports, and here will alert on the most
suspicious ports that may be open for any device.
"""
suspicious_ports = [21, 22, 23, 2323, 25, 110, 111, 135]

# A list of suspicious strings to search for in plaintext
suspicious_strings = ["password", "passwd", "email", "e-mail", "username", "usrname", "api_token"]


class PacketPrivacyPort(PacketPrivacy):
    """
    This privacy detection is called on every packet coming through tinyHIPPO. It alerts on suspicious ports and scans
    plaintext in port 80 connections for credit cards, social security numbers, emails, and suspicious keywords.
    """

    def __call__(self, packet_input: Packet):
        """
        Handles the privacy detection process and alerting
        :param packet_input: The current packet to analyze
        """
        self.packet = packet_input
        is_TCP = self.packet.haslayer(TCP)
        is_UDP = self.packet.haslayer(UDP)

        # Perform TCP and UDP checks
        if is_TCP or is_UDP:
            proto_type = TCP if is_TCP else UDP

            # Scan for using port 80 and the plaintext for privacy leaks
            if (self.packet[proto_type].dport == 80) or (self.packet[proto_type].sport == 80):
                alert_port_80 = Alert(None, "Sending data over unencrypted port.", AlertType.PRIVACY, Severity.ALERT)
                if self.packet[proto_type].dport == 80:
                    vuln_target = "dst"
                else:
                    vuln_target = "src"
                alert_port_80.device_mac = self.packet[Ether][vuln_target]
                alert_port_80.device_ip = self.packet[IP][vuln_target]
                alert_port_80.alert()
                self.__scan_plaintext(proto_type, vuln_target)

            # Monitor suspicious ports
            if self.packet[proto_type].dport in suspicious_ports:
                alert_suspicious_ports = Alert(None, "Suspicious destination port used: " +
                                               str(self.packet[proto_type].dport), AlertType.PRIVACY, Severity.WARN)
                alert_suspicious_ports.device_mac = self.packet[Ether].dst
                alert_suspicious_ports.device_ip = self.packet[IP].dst
                alert_suspicious_ports.alert()

    def __scan_plaintext(self, proto_type, vuln_target):
        """
        Scan plaintext for privacy leaks and alert on findings: credit cards, social security numbers, emails,
        and suspicious keywords. Note that there is a chance for false positives with credit cards and SSNs,
        because they're just numbers
        :param proto_type: Either TCP or UDP
        :param vuln_target: Either "src" or "dst", depending on where the plaintext vulnerability originiated from
        """
        # Try to get the payload
        try:
            self.payload = str(self.packet[proto_type].payload)
        except Exception as e:
            run_config.log_event.info('Exception raised: ' + str(e))
            return

        # Use a regex to look for credit cards, needs a non-number before and after the numbers
        self.__regex_alert("[\D](?:[0-9]{4}-){3}[0-9]{4}[\D]|[\D][0-9]{16}[\D]", "Credit card information found in a "
                                                                                 "plaintext packet.", vuln_target)

        # Use a regex to look for SSNs, needs a non-number before and after the numbers
        self.__regex_alert("[\D][0-9]{9}[\D]|[\D][0-9]{3}-[0-9]{2}-[0-9]{4}[\D]", "SSN information found in a "
                                                                                  "plaintext packet.", vuln_target)

        # Use a regex to look for emails - this is not a huge privacy leak, but still mentionable
        # The email will not be included in the alert for privacy reasons
        self.__regex_alert("[^@]+@[^@]+\.[^@]+", "Email information found in a plaintext packet.", vuln_target)

        # Search for specific words to alert on
        for keyword in suspicious_strings:
            if keyword in self.payload:
                alert_keyword = Alert(None, f'Suspicious keyword found in a plaintext packet: {keyword}',
                                      AlertType.PRIVACY, Severity.ALERT)
                alert_keyword.device_mac = self.packet[Ether][vuln_target]
                alert_keyword.device_ip = self.packet[IP][vuln_target]
                alert_keyword.alert()

    def __regex_alert(self, regex_string, alert_string, vuln_target):
        """
        Scan the payload with the given regex string and alert if necessary
        :param regex_string: The regex string to scan the paylaod with
        :param alert_string: The string to pass into the Alert object as the description for the event
        :param vuln_target: Either "src" or "dst", depending on where the plaintext vulnerability originiated from
        """
        if re.search(regex_string, self.payload):
            alert_regex = Alert(None, alert_string, AlertType.PRIVACY, Severity.ALERT)
            alert_regex.device_mac = self.packet[Ether][vuln_target]
            alert_regex.device_ip = self.packet[IP][vuln_target]
            alert_regex.alert()


"""
Sources
https://stackoverflow.com/questions/46079770/validate-card-numbers-using-regex-python
https://stackoverflow.com/questions/48776006/regex-to-match-ssn-in-python
https://stackoverflow.com/questions/8022530/how-to-check-for-valid-email-address
"""
