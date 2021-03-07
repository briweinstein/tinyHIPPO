#! /usr/bin/env python3
from scapy.all import sniff
from scapy.utils import raw
import re, sys, json, time
from privacy_analysis.packet_privacy_class import Privacy_Analysis_Packet
from privacy_analysis.system_privacy_class import Privacy_Analysis_System

# Filepath to the config file to pull the MAC addresses from
config_file_path = "config.json"

# Base location of where packets will be stored
packet_base_location = "../packets_captured"

# Number of packets to capture, 0 is infinite
num_packets = 2

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
  privacy_system_obj = Privacy_Analysis_System()
  privacy_system_obj.analyze_system_configs()

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

  with open(config_file_path, "r") as config_file:
    config_json = json.load(config_file)

  # Throw an error on a bad MAC address or add it to the global MAC address storage
  # TODO: The validation likely won't go in this script, but we'll keep it here for now
  global mac_addrs
  for addr in config_json["mac_addrs"]:
    if not re.match("[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", addr.lower()):
      sys.exit("Provided address " + addr + " is not a vaid MAC address.")
    else:
      mac_addrs.append(addr.lower())

##############################################################################################
### Export packets
##############################################################################################

def packet_parse(packet):
  privacy_packet_obj = Privacy_Analysis_Packet(packet)
  privacy_packet_obj.process_packet()

##############################################################################################
### Call main()
##############################################################################################

main()

# Sources:
# https://linuxsecurityblog.com/2016/02/04/sniffing-access-points-and-mac-addresses-using-python/
# https://stackoverflow.com/questions/24386000/how-to-filter-by-ethernet-mac-address
# https://stackoverflow.com/questions/7629643/how-do-i-validate-the-format-of-a-mac-address


