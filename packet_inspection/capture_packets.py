#! /usr/bin/env python3
from scapy.all import sniff
from scapy.utils import hexdump
import argparse, re, sys

# To run this program with the IoT MAC addresses for Capstone:
# sudo ./capture_packets.py A0:9F:10:1B:D7:05 AC:83:F3:BC:A7:61

# Validated MAC addresses given as input
mac_addrs = []

##############################################################################################
### Main function
##############################################################################################

# Perform packet capture and parse in the following order:
#   1) Parse and validate arguments
#   2) Capture IoT packets only
#   3) Parse packets
def main():
  # 1) Parse and validate arguments
  parse_validate_arguments()

  # Note: Steps 2 and 3 happen simultaneously in the "sniff()" call, but are separated for clarity
  # 2) Capture IoT packets only with crafted sniff
  print("Capturing IoT packets only")
  # 3) Parse packets
  sniff(iface="wlan0", lfilter=lambda packet: packet.src in mac_addrs, prn=packet_parse, count=2)

##############################################################################################
### Parse and validate arguments
##############################################################################################

# Take in a list of strings as input and confirm they are MAC addresses
def parse_validate_arguments():
  print("Parsing and validating arguments")
  parser = argparse.ArgumentParser(description="Accept MAC addresses as input to an OpenWrt package.")
  parser.add_argument("mac_addresses", nargs="+", help="A list of MAC addresses belonging to IoT devices to monitor.")
  args = parser.parse_args()

  # Throw an error on a bad MAC address or add it to the global MAC address storage
  # TODO: Not sure if the package can throw errors like this @Martin
  global mac_addrs
  for addr in args.mac_addresses:
    if not re.match("[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", addr.lower()):
      sys.exit("Provided address " + addr + " is not a vaid MAC address.")
    else:
      mac_addrs.append(addr.lower())

##############################################################################################
### Parse packets
##############################################################################################

# Parse the IoT packets
def packet_parse(packet):
  print("Parsing packet")
  print("IoT MAC Addresses: " + ", ".join(mac_addrs))
  print(packet)
  
  # scapy packet stuff to try
  packet.show()
  print("###########################")
  hexdump(packet)
  print("###########################")
  print(packet.src)
  print("###########################")

##############################################################################################
### Call main()
##############################################################################################

main()

# Sources:
# https://docs.python.org/3/library/argparse.html
# https://linuxsecurityblog.com/2016/02/04/sniffing-access-points-and-mac-addresses-using-python/
# https://stackoverflow.com/questions/24386000/how-to-filter-by-ethernet-mac-address
# https://stackoverflow.com/questions/7629643/how-do-i-validate-the-format-of-a-mac-address


