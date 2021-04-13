#! /usr/bin/env python3
from scapy.all import sniff
from scapy.packet import Packet
from scapy.layers.inet import Ether
from src import run_config
from src.database.models import DeviceInformation
from src.privacy_analysis.packet_analysis.packet_privacy_port import PacketPrivacyPort
from src.privacy_analysis.system_analysis.system_privacy_dropbear_config import SystemPrivacyDropbearConfig
from src.privacy_analysis.system_analysis.system_privacy_encryption import SystemPrivacyEncryption
from src.privacy_analysis.system_analysis.system_privacy_package_upgrades import SystemPrivacyPackageUpgrades
from src.privacy_analysis.system_analysis.system_privacy_root_password import SystemPrivacyRootPassword
from src.signature_detection.ip_signature import IPSignature
from src.signature_detection.mac_address_signature import MACAddressSignature
from src.signature_detection.signature_detector import SignatureDetector
from src.dashboard.alerts.alert import Alert, Severity, AlertType

# TODO: Allow user to enable/disable certain rules
rules_packet_privacy = [PacketPrivacyPort()]
rules_system_privacy = [SystemPrivacyDropbearConfig(), SystemPrivacyEncryption(), SystemPrivacyPackageUpgrades(),
                        SystemPrivacyRootPassword()]
rules_scanning_privacy = []
ids_signatures = [IPSignature("192.168.1.0/24"), MACAddressSignature()]
signature_detector = SignatureDetector(ids_signatures)
# Number of packets to capture, 0 is infinite
num_packets = 0


def main():
    """
    Main loop of the program, does the following
    1. Validates the users given mac addresses
    2. Runs system privacy checks
    3. Sniffs packets on "wlan0" and analyzes the packet against signatures and privacy rules
    :return: nothing
    """

    # 2) Perform a system configuration security check
    for rule in rules_system_privacy:
        rule()

    mac_addresses = DeviceInformation.get_mac_addresses()
    # Note: Steps 2 and 3 happen simultaneously in the "sniff()" call, but are separated for clarity
    # 2) Capture IoT packets only with crafted sniff
    print("Capturing IoT packets only")
    # 3) Export packets
    # TODO: Make sure iface is set to the correct interface. May be different in some routers
    sniff(iface=run_config.sniffing_interface, lfilter=lambda packet: (packet.src in mac_addresses) or (packet.dst in mac_addresses),
          prn=packet_parse, count=num_packets)


def packet_parse(packet: Packet):
    """
    Runs privacy analysis rules and checks packet against IDS signatures
    :param packet: packet to analyze
    :return: nothing
    """
    for rule in rules_packet_privacy:
        try:
            rule(packet)
        except Exception as e:
            # TODO: refine so a specific error message can be logged
            run_config.log_event.info('Exception raised in a privacy rule check: ' + str(e))
    # For each triggered signature generate an alert for the user
    try:
        triggered_rules = signature_detector.check_signatures(packet)
        if len(triggered_rules) > 0:
            for triggered_rule in triggered_rules:
                is_dst = packet[Ether].src in DeviceInformation.get_mac_addresses()
                alert_object = Alert(packet, triggered_rule.msg, AlertType.IDS, Severity.ALERT, is_dst)
                alert_object.alert()
    except Exception as e:
        # TODO: refine so a specific error message can be logged
        run_config.log_event.info('Exception raised in an IDS rule check: ' + str(e))


# call main
if __name__ == '__main__':
    main()

# Sources:
# https://linuxsecurityblog.com/2016/02/04/sniffing-access-points-and-mac-addresses-using-python/
# https://stackoverflow.com/questions/24386000/how-to-filter-by-ethernet-mac-address
# https://stackoverflow.com/questions/7629643/how-do-i-validate-the-format-of-a-mac-address
