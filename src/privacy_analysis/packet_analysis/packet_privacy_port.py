#! /usr/bin/env python3
from src.privacy_analysis.packet_analysis import PacketPrivacy
from scapy.all import TCP, UDP
from scapy.all import Packet

# from dashboard.alerts.alert import alert

suspicious_ports = [21, 22, 23, 2323, 25, 110, 111, 135]


# TODO: separate sus ports for TCP/UDP?

class PacketPrivacyPort(PacketPrivacy):
    def __call__(self, packet: Packet):
        is_TCP = packet.haslayer(TCP)
        is_UDP = packet.haslayer(UDP)

        # Perform TCP and UDP checks
        if is_TCP or is_UDP:
            proto_type = TCP if is_TCP else UDP

            # Scan for using port 80 and the plaintext for privacy leaks
            if (packet[proto_type].dport == 80) or (packet[proto_type].sport == 80):
                # TODO: send_alert("Sending data over unencrypted port.")
                self.__scan_plaintext(packet)

            # Monitor suspicious ports
            print("Monitoring suspicious ports")
            if packet[proto_type].dport in suspicious_ports:
                # TODO: send_alert("Suspicious destination port used: " + self.packet[proto_type].dport)
                print("Alert on bad port")

    # Scan the plaintext for privacy leaks
    # TODO: regex for email, SSN, credit card
    def __scan_plaintext(self, packet):
        try:
            if (packet[proto_type].dport == 80) or (packet[proto_type].sport == 80):
                print(packet[proto_type].payload)
        except:
            print("plaintext not found")
            print(packet[proto_type].payload)
            return
