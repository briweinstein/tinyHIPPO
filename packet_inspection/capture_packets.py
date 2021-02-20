#! /usr/bin/env python3
from scapy import *
import argparse, re, sys

# TODO: Does the router need to be in monitor mode?

##############################################################################################
### Main function
##############################################################################################

# Perform packet capture and parse in the following order:
#   1) Parse and validate arguments
#   2) Capture IoT packets only
#   3) Parse packets
def main():
  # 1) Parse and validate arguments
  print("Parsing arguments")
  mac_addrs = parse_validate_arguments()
  
  # 2) Capture IoT packets only
  print("Capturing IoT packets only")
  # Sniff
  #sniff(iface="mon0",prn=packet_capture)
  
  # 3) Parse packets
  #parse_packets()

##############################################################################################
### Parse and validate arguments
##############################################################################################

# Take in a list of strings as input and confirm they are MAC addresses
def parse_validate_arguments():
  parser = argparse.ArgumentParser(description="Accept MAC addresses as input to an OpenWrt package.")
  parser.add_argument("mac_addresses", nargs="+", help="A list of MAC addresses belonging to IoT devices to monitor.")
  args = parser.parse_args()

  # Throw an error on a bad MAC address
  # TODO: Not sure if the package can throw errors like this @Martin
  for addr in args.mac_addresses:
    # https://stackoverflow.com/questions/7629643/how-do-i-validate-the-format-of-a-mac-address
    if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", addr.lower()):
      sys.exit("Provided address " + addr + " is not a vaid MAC address.")

##############################################################################################
### Capture IoT packets only
##############################################################################################

# Take in a list of confirmed MAC addresses to captue packets for
def packet_capture():
  # Stuff

##############################################################################################
### Parse packets
##############################################################################################

# Parse the IoT packets
def parse_packets():
  # Stuff

##############################################################################################
### Call main()
##############################################################################################

main()

# Sources:
# https://docs.python.org/3/library/argparse.html



