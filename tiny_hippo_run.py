#! /usr/bin/env python3
import pathlib
import click
from scapy.utils import rdpcap
import random
import math

from time import sleep
from scapy.all import sniff
from scapy.packet import Packet
from scapy.layers.inet import Ether, TCP
from src import run_config, db
from src.database.models import DeviceInformation
from src.privacy_analysis.packet_analysis.packet_privacy_port import PacketPrivacyPort
from src.privacy_analysis.system_analysis.system_privacy_dropbear_config import SystemPrivacyDropbearConfig
from src.privacy_analysis.system_analysis.system_privacy_encryption import SystemPrivacyEncryption
from src.privacy_analysis.system_analysis.system_privacy_package_upgrades import SystemPrivacyPackageUpgrades
from src.privacy_analysis.system_analysis.system_privacy_root_password import SystemPrivacyRootPassword
from src.privacy_analysis.scanning_analysis.scanning_privacy_nmap_passive import ScanningPrivacyNmapPassive
from src.signature_detection.ip_signature import IPSignature
from src.signature_detection.mac_address_signature import MACAddressSignature
from src.signature_detection.signature_detector import SignatureDetector
from src.dashboard.alerts.alert import Alert, Severity, AlertType
from src.anamoly_detection.anomaly_engine import AnomalyEngine

# TODO: Allow user to enable/disable certain rules
rules_packet_privacy = [PacketPrivacyPort()]
rules_system_privacy = [SystemPrivacyDropbearConfig(), SystemPrivacyEncryption(), SystemPrivacyPackageUpgrades(),
                        SystemPrivacyRootPassword()]
rules_scanning_privacy = [ScanningPrivacyNmapPassive()]
ids_signatures = [IPSignature("192.168.1.0/24"), MACAddressSignature()]
signature_detector = SignatureDetector(ids_signatures)
# Number of packets to capture, 0 is infinite
num_packets = 0
anomaly_engine = AnomalyEngine(db)

# Testing command line argument values
percent_malicious_packets = 0
malicious_packets_plaintext = []
malicious_packets_port = []
malicious_packet_count = 0
packet_count = 0
total_malicious_packet_count = 0
total_malicious_port_count = 0
total_malicious_plaintext_count = 0


@click.command()
@click.option("--arg_pcap_file_benign", "-b", required=True, type=str)
@click.option("--arg_pcap_file_malicious_plaintext", "-mplain", required=True, type=str)
@click.option("--arg_pcap_file_malicious_port_only", "-mport", required=True, type=str)
@click.option("--arg_percent_malicious_packets", "-p", required=True, type=int)
def main(arg_pcap_file_benign: str, arg_pcap_file_malicious_plaintext: str, arg_pcap_file_malicious_port_only: str,
         arg_percent_malicious_packets: int):
    global malicious_packets_plaintext, malicious_packets_port, percent_malicious_packets
    """
    Main loop of the program, does the following
    1. Validates the users given mac addresses
    2. Runs system privacy checks
    3. Runs scanning analysis of the IoT devices
    4. Sniffs packets on "wlan0" and analyzes the packet against signatures and privacy rules
    :return: nothing
    """
    # Set the global testing command line argument values
    pcap_file_benign = arg_pcap_file_benign
    percent_malicious_packets = arg_percent_malicious_packets
    print("Going to read")
    malicious_packets_plaintext = sniff(offline=str(arg_pcap_file_malicious_plaintext))
    malicious_packets_port = sniff(offline=str(arg_pcap_file_malicious_port_only))
    print("Finished reading")

    # 2) Perform a system configuration security check
    try:
        for rule in rules_system_privacy:
            # rule()
            print("Not running rule: " + str(rule))
    except Exception as e:
        run_config.log_event.info(f"Exception when running system privacy rule {e}")

    mac_addresses = DeviceInformation.get_mac_addresses()
    # Note: Steps 2 and 3 happen simultaneously in the "sniff()" call, but are separated for clarity
    # 2) Capture IoT packets only with crafted sniff
    # 3) Perform a scanning analysis of the IoT devices
    # ip_to_mac = _pair_ip_to_mac(mac_addresses)
    try:
        for rule in rules_scanning_privacy:
            # rule(ip_to_mac)
            print("Not running rule: " + str(rule))
    except Exception as e:
        run_config.log_event.info(f"Exception when running scanning privacy rule {e}")
    # 4) Capture IoT packets only with crafted sniff
    print("Capturing IoT packets only")
    sniff(offline=str(pcap_file_benign), lfilter=_sniff_filter, prn=packet_combo, store=0)
    print("Finished Capturing Packets")
    print("Total Packets: " + str(packet_count))
    print("Total Malicious Packets: " + str(total_malicious_packet_count))
    print("Total Malicious Packets Plaintext: " + str(total_malicious_plaintext_count))
    print("Total Malicious Packets Ports: " + str(total_malicious_port_count))


def _sniff_filter(packet: Packet):
    results = DeviceInformation.get_mac_addresses()
    return packet.src in results or packet.dst in results


def packet_combo(packet_benign: Packet):
    global malicious_packets_plaintext, malicious_packets_port, packet_count, total_malicious_packet_count
    global total_malicious_port_count, total_malicious_plaintext_count
    # Determine if a malicious packet should be sent
    send_malicious = random.randint(1, 100) <= percent_malicious_packets
    # Send the malicious packet if needed
    packet_count += 1
    if send_malicious:
        try:
            total_malicious_packet_count += 1
            # Get the next malicious packet
            send_plaintext = random.randint(1, 100) <= 50
            if send_plaintext:
                curr_malicious_packet = get_next_malicious_packet(packet_benign, malicious_packets_plaintext)
                if "uname=username-hello&pass=helloworld" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 1
                elif "uname=tinyHIPPO&pass=password123" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 1
                elif "uname=tinyHIPPO1234567890123&pass=password" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 1
                elif "uname=username&pass=root" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 1
                elif "urname=tinyHIPPO&ucc=2111312216&uemail=user%40gmail.com&uphone=%28555%29555-5555&uaddress=address+to+home&update=update" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 1
                elif "urname=Frank+Router&ucc=1234900933448867&uemail=router%40hotmail.org&uphone=%28555%291115555&uaddress=address+to+home&update=update" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 2
                elif "urname=Frank+Router2&ucc=1234900933448867&uemail=router%40org&uphone=5551115555&uaddress=address+to+home&update=update" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 1
                elif "name=test&text=My+password+is+test%21&submit=add+message" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 1
                elif "Social+Security+Number" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 1
                elif "name=test&text=I+love+having+an+api_token&submit=add+message" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 1
                elif "name=test&text=Looking+forward+to+sharing+my+e-mail+with+the+whole+world%21&submit=add+message" in str(curr_malicious_packet[TCP].payload):
                    total_malicious_plaintext_count += 1
                curr_malicious_packet.time = packet_benign.time
            else:
                curr_malicious_packet = get_next_malicious_packet(packet_benign, malicious_packets_port)
                curr_malicious_packet.time = packet_benign.time
                total_malicious_port_count += 1
            # Process the malicious packet
            packet_parse(curr_malicious_packet)
        except:
            print("error parsing packet, woopsies")
    else:
        # Send the given benign packet
        packet_parse(packet_benign)


def get_next_malicious_packet(packet_benign: Packet, malicious_packets):
    global malicious_packet_count, total_malicious_plaintext_count
    if malicious_packet_count >= len(malicious_packets):
        malicious_packet_count = 0
    curr_malicious_packet = malicious_packets[malicious_packet_count]
    malicious_packet_count = malicious_packet_count + 1
    if "Ethernet" in curr_malicious_packet and "Ethernet" in packet_benign:
        curr_malicious_packet["Ethernet"].dst = packet_benign["Ethernet"].dst
        curr_malicious_packet["Ethernet"].src = packet_benign["Ethernet"].src
    elif "Ethernet" in curr_malicious_packet and "EAPOL" in packet_benign:
        curr_malicious_packet["Ethernet"].dst = packet_benign["EAPOL"].dst
        curr_malicious_packet["Ethernet"].src = packet_benign["EAPOL"].src
    """
    else:
        curr_malicious_packet.show()
        packet_benign.show()
    """
    return curr_malicious_packet


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
        # run_config.log_event.info('Exception raised in an IDS rule check: ' + str(e))
        ...

    # For each packet, pass through frequency detection engine
    try:
        anomaly_engine.check_signatures(packet)
    except Exception as e:
        run_config.log_event.info('Exception raised in an Anomaly Engine check: ' + str(e))



def _pair_ip_to_mac(mac_addrs):
    """
    Uses the "arp" system call to pair IoT MAC addrs to their current IP addrs
    :return: dict of IPs to MACs
    """
    # Get ARP data from the system and parse out the IP and MAC addrs
    with open("/proc/net/arp", "r") as file:
        arp_data = file.read()
    arp_lines = arp_data.split("\n")
    ip_to_mac_all = {}
    for line in arp_lines[1:-1]:
        line_parsed = list(filter(None, line.split(" ")))
        ip_to_mac_all[line_parsed[0]] = line_parsed[3]

    # Filter out non-IoT devices from ip_to_mac_all
    ip_to_mac_iot = {}
    for ip in ip_to_mac_all.keys():
        if ip_to_mac_all[ip] in mac_addrs:
            ip_to_mac_iot[ip] = ip_to_mac_all[ip]
    return ip_to_mac_iot


# call main
if __name__ == '__main__':
    main()

# Sources:
# https://linuxsecurityblog.com/2016/02/04/sniffing-access-points-and-mac-addresses-using-python/
# https://stackoverflow.com/questions/24386000/how-to-filter-by-ethernet-mac-address
# https://stackoverflow.com/questions/7629643/how-do-i-validate-the-format-of-a-mac-address
