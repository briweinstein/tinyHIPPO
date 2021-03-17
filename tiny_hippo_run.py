#! /usr/bin/env python3
from scapy.all import sniff
from scapy.packet import Packet
from scapy.layers.inet import Ether
from src import run_config
import re
from src.privacy_analysis.packet_analysis.packet_privacy_port import PacketPrivacyPort
from src.privacy_analysis.system_analysis.system_privacy_dropbear_config import SystemPrivacyDropbearConfig
from src.privacy_analysis.system_analysis.system_privacy_encryption import SystemPrivacyEncryption
from src.privacy_analysis.system_analysis.system_privacy_package_upgrades import SystemPrivacyPackageUpgrades
from src.privacy_analysis.system_analysis.system_privacy_root_password import SystemPrivacyRootPassword
from src.signature_detection.ip_signature import IPSignature
from src.signature_detection.mac_address_signature import MACAddressSignature
from src.signature_detection.signature_detector import SignatureDetector
from src.dashboard.alerts.alert import Alert, SEVERITY, ALERT_TYPE

# TODO: Allow user to enable/disable certain rules
rules_packet_privacy = [PacketPrivacyPort()]
rules_system_privacy = [SystemPrivacyDropbearConfig(), SystemPrivacyEncryption(), SystemPrivacyPackageUpgrades(),
                        SystemPrivacyRootPassword()]
rules_scanning_privacy = []
ids_signatures = [IPSignature("192.168.1.0/24"), MACAddressSignature()]
signature_detector = SignatureDetector(ids_signatures)
# Number of packets to capture, 0 is infinite
num_packets = 1

# Validated MAC addresses given in config file
mac_addrs = []


def main():
    """
    Main loop of the program, does the following
    1. Validates the users given mac addresses
    2. Runs system privacy checks
    3. Sniffs packets on "wlan0" and analyzes the packet against signatures and privacy rules
    :return: nothing
    """
    # 1) Pull and validate MAC addresses
    pull_and_validate_addrs()

    # 2) Perform a system configuration security check
    for rule in rules_system_privacy:
        rule()

    # Note: Steps 2 and 3 happen simultaneously in the "sniff()" call, but are separated for clarity
    # 2) Capture IoT packets only with crafted sniff
    print("Capturing IoT packets only")
    # 3) Export packets
    sniff(iface="wlan0", lfilter=lambda packet: (packet.src in mac_addrs) or (packet.dst in mac_addrs),
          prn=packet_parse, count=num_packets)


def pull_and_validate_addrs():
    """
    Validates the mac addresses given by the user in the dashboard
    :return: nothing
    """
    print("Pulling and validating MAC addresses")

    # Throw an error on a bad MAC address or add it to the global MAC address storage
    # TODO: The validation likely won't go in this script, but we'll keep it here for now
    global mac_addrs
    for addr in run_config.mac_addrs:
        if not re.match("[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", addr.lower()):
            print("Provided address " + addr + " is not a vaid MAC address.")
        mac_addrs.append(addr.lower())


def packet_parse(packet: Packet):
    """
    Runs privacy analysis rules and checks packet against IDS signatures
    :param packet: packet to analyze
    :return: nothing
    """
    for rule in rules_packet_privacy:
        rule(packet)
    # For each triggered signature generate an alert for the user
    triggered_rules = signature_detector.check_signatures(packet)
    if len(triggered_rules) > 0:
        for triggered_rule in triggered_rules:
            is_dst = packet[Ether].src in mac_addrs
            alert_object = Alert(packet, triggered_rule.msg, ALERT_TYPE.IDS, SEVERITY.ALERT, is_dst)
            alert_object.alert()


# call main
main()

# Sources:
# https://linuxsecurityblog.com/2016/02/04/sniffing-access-points-and-mac-addresses-using-python/
# https://stackoverflow.com/questions/24386000/how-to-filter-by-ethernet-mac-address
# https://stackoverflow.com/questions/7629643/how-do-i-validate-the-format-of-a-mac-address
