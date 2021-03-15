#! /usr/bin/env python3
from scapy.all import sniff
from config import Config
import re, sys
from src.privacy_analysis.packet_analysis import PacketPrivacyPort
from src.privacy_analysis.system_analysis import SystemPrivacyDropbearConfig
from src.privacy_analysis.system_analysis import SystemPrivacyEncryption
from src.privacy_analysis.system_analysis import SystemPrivacyPackageUpgrades
from src.privacy_analysis.system_analysis import SystemPrivacyRootPassword

rules_packet_privacy = [PacketPrivacyPort]
rules_system_privacy = [SystemPrivacyDropbearConfig, SystemPrivacyEncryption, SystemPrivacyPackageUpgrades, SystemPrivacyRootPassword]
rules_scanning_privacy = []

# Number of packets to capture, 0 is infinite
num_packets = 1

# Validated MAC addresses given in config file
mac_addrs = []

##############################################################################################
### Main function
##############################################################################################

# Perform packet capture and parse in the following order:
#   1) Pull from config file and validate arguments
#   2) Capture IoT packets only
#   3) Export packets to files as hex
def main():
  # 1) Pull and validate MAC addresses
  pull_and_validate_addrs()

  # 2) Perform a system configuration security check
  for rule in rules_system_privacy:
    rule()

  # Note: Steps 2 and 3 happen simultaneously in the "sniff()" call, but are separated for clarity
  # 2) Capture IoT packets only with crafted sniff
  print("Capturing IoT packets only")
  # 3) Export packets
  sniff(iface="wlan0", lfilter=lambda packet: (packet.src in mac_addrs) or (packet.dst in mac_addrs), prn=packet_parse, count=num_packets)

##############################################################################################
### Pull and validate MAC addresses
##############################################################################################

# Take in a list of strings as input and confirm they are MAC addresses
def pull_and_validate_addrs():
  print("Pulling and validating MAC addresses")

  # Entrypoint file
  run_config = Config()

  # Throw an error on a bad MAC address or add it to the global MAC address storage
  # TODO: The validation likely won't go in this script, but we'll keep it here for now
  global mac_addrs
  for addr in run_config.mac_addrs:
    if not re.match("[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", addr.lower()):
      sys.exit("Provided address " + addr + " is not a vaid MAC address.")
    else:
      mac_addrs.append(addr.lower())

##############################################################################################
### Analyze packet privacy
##############################################################################################

def packet_parse(packet):
  for rule in rules_packet_privacy:
    rule(packet)

##############################################################################################
### Call main()
##############################################################################################

main()

# Sources:
# https://linuxsecurityblog.com/2016/02/04/sniffing-access-points-and-mac-addresses-using-python/
# https://stackoverflow.com/questions/24386000/how-to-filter-by-ethernet-mac-address
# https://stackoverflow.com/questions/7629643/how-do-i-validate-the-format-of-a-mac-address


