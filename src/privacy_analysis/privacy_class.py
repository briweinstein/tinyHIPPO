#! /usr/bin/env python3
from scapy.all import sniff

class Privacy_Analysis:
  def __init__(self, packet):
    self.packet = packet

  def process_packet(self):
    print("Processing packet")
    print(self.packet.src)
